#include "gc.h"
#include "goroutine.h"
#include "ast.h"
#include <iostream>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <map>
#include <signal.h>
#include <pthread.h>

// Thread-local current goroutine (defined in goroutine.cpp)
extern thread_local std::shared_ptr<Goroutine> currentTask;

// Signal handler for GC memory fence checkpoint
extern "C" void gc_checkpoint_signal_handler(int sig) {
    // The signal itself creates a memory fence - all pending writes
    // must be visible before the handler executes (OS guarantees this)
    
    if (currentTask && currentTask->gcState) {
        // Increment checkpoint counter atomically
        // GC thread will wait for this to confirm the goroutine has reached the checkpoint
        currentTask->gcState->checkpointCounter.fetch_add(1, std::memory_order_seq_cst);
    }
    
    // Execute explicit memory fence for extra safety
    // This ensures all prior writes are globally visible
    std::atomic_thread_fence(std::memory_order_seq_cst);
}

// MetadataRegistry implementation
MetadataRegistry& MetadataRegistry::getInstance() {
    static MetadataRegistry instance;
    return instance;
}

MetadataRegistry::~MetadataRegistry() {
    // Clean up all allocated metadata
    for (auto& [name, metadata] : classMetadata) {
        if (metadata) {
            // Free field metadata
            delete[] metadata->fields;
            
            // Free method closures
            if (metadata->methodClosures) {
                for (int i = 0; i < metadata->numMethods; i++) {
                    if (metadata->methodClosures[i]) {
                        delete[] reinterpret_cast<uint8_t*>(metadata->methodClosures[i]);
                    }
                }
                delete[] metadata->methodClosures;
            }
            
            // Free parent info
            if (metadata->parentNames) {
                for (int i = 0; i < metadata->numParents; i++) {
                    if (metadata->parentNames[i]) {
                        free(const_cast<char*>(metadata->parentNames[i]));
                    }
                }
                delete[] metadata->parentNames;
            }
            if (metadata->parentOffsets) {
                delete[] metadata->parentOffsets;
            }
            
            // Free class name
            if (metadata->className) {
                free(const_cast<char*>(metadata->className));
            }
            
            delete metadata;
        }
    }
}

void MetadataRegistry::buildClassMetadata(const std::map<std::string, ClassDeclNode*>& classRegistry) {
    std::lock_guard<std::mutex> lock(registryMutex);
    
    std::cout << "Building class metadata for " << classRegistry.size() << " classes" << std::endl;
    
    for (const auto& [className, classDecl] : classRegistry) {
        // Build comprehensive field list (all fields for dynamic access)
        std::vector<VarMetadata> allFields;
        
        // Add parent class fields first (in inheritance order)
        for (ClassDeclNode* parent : classDecl->parentRefs) {
            int parentOffset = classDecl->parentOffsets[parent->className];
            for (const auto& [fieldName, fieldInfo] : parent->fields) {
                void* typeInfo = nullptr;
                if (fieldInfo.type == DataType::OBJECT && fieldInfo.classNode) {
                    typeInfo = fieldInfo.classNode; // Temp: will resolve to ClassMetadata later
                }
                
                std::string fullFieldName = parent->className + "::" + fieldName;
                // Field offset = header + field offset (no method closures in instance, just pointers)
                // Actually, instances have closure POINTERS, not embedded closures
                // So the offset calculation needs to account for method closure pointers
                int absoluteOffset = 16 + (classDecl->vtable.size() * 8) + parentOffset + fieldInfo.offset;
                allFields.emplace_back(
                    absoluteOffset, 
                    fieldInfo.type, 
                    typeInfo,
                    strdup(fullFieldName.c_str())  // Allocate permanent storage for name
                );
            }
        }
        
        // Add own fields
        for (const auto& [fieldName, fieldInfo] : classDecl->fields) {
            void* typeInfo = nullptr;
            if (fieldInfo.type == DataType::OBJECT && fieldInfo.classNode) {
                typeInfo = fieldInfo.classNode; // Temp: will resolve to ClassMetadata later
            }
            
            // Field offset = header + closure pointers + field offset
            int absoluteOffset = 16 + (classDecl->vtable.size() * 8) + fieldInfo.offset;
            allFields.emplace_back(
                absoluteOffset, 
                fieldInfo.type, 
                typeInfo,
                strdup(fieldName.c_str())  // Allocate permanent storage for name
            );
        }
        
        // Build simple method closure array
        Closure** methodClosures = nullptr;
        if (!classDecl->vtable.empty()) {
            methodClosures = new Closure*[classDecl->vtable.size()];
            
            for (size_t i = 0; i < classDecl->vtable.size(); i++) {
                const auto& vtEntry = classDecl->vtable[i];
                
                // Calculate closure size: size field + func_addr + scope pointers
                size_t closureSize = 16; // size field + func_addr
                if (vtEntry.method && vtEntry.method->allNeeded.size() > 0) {
                    closureSize += vtEntry.method->allNeeded.size() * 8;
                }
                
                // Allocate closure
                uint8_t* closureData = new uint8_t[closureSize];
                memset(closureData, 0, closureSize);
                
                Closure* closure = reinterpret_cast<Closure*>(closureData);
                closure->size = closureSize;
                closure->funcAddr = nullptr; // Will be patched during codegen
                
                methodClosures[i] = closure;
                
                std::cout << "    - Method '" << vtEntry.methodName << "' closure size: " 
                          << closureSize << " bytes (needs " 
                          << (vtEntry.method ? vtEntry.method->allNeeded.size() : 0) 
                          << " scopes)" << std::endl;
            }
        }
        
        // Build parent info
        const char** parentNames = nullptr;
        int* parentOffsets = nullptr;
        int numParents = classDecl->parentRefs.size();
        if (numParents > 0) {
            parentNames = new const char*[numParents];
            parentOffsets = new int[numParents];
            for (size_t i = 0; i < classDecl->parentRefs.size(); i++) {
                parentNames[i] = strdup(classDecl->parentRefs[i]->className.c_str());
                parentOffsets[i] = classDecl->parentOffsets[classDecl->parentRefs[i]->className];
            }
        }
        
        // Allocate and populate field metadata array
        VarMetadata* fieldsArray = nullptr;
        if (!allFields.empty()) {
            fieldsArray = new VarMetadata[allFields.size()];
            for (size_t i = 0; i < allFields.size(); i++) {
                fieldsArray[i] = allFields[i];
            }
        }
        
        // Create ClassMetadata with simple closure array
        ClassMetadata* metadata = new ClassMetadata(
            strdup(classDecl->className.c_str()),
            allFields.size(),
            fieldsArray,
            classDecl->totalSize,
            classDecl->vtable.size(),
            methodClosures,
            numParents,
            parentNames,
            parentOffsets
        );
        
        classMetadata[className] = metadata;
        classDecl->runtimeMetadata = metadata;  // Link back to AST
        
        std::cout << "  - Created metadata for class '" << className 
                  << "' with " << allFields.size() << " fields, " 
                  << classDecl->vtable.size() << " methods, " 
                  << numParents << " parents" << std::endl;
    }
    
    // Second pass: resolve ClassDeclNode pointers to ClassMetadata pointers
    for (auto& [className, metadata] : classMetadata) {
        for (int i = 0; i < metadata->numFields; i++) {
            if (metadata->fields[i].type == DataType::OBJECT && metadata->fields[i].typeInfo) {
                ClassDeclNode* classDecl = static_cast<ClassDeclNode*>(metadata->fields[i].typeInfo);
                auto it = classMetadata.find(classDecl->className);
                if (it != classMetadata.end()) {
                    metadata->fields[i].typeInfo = it->second;
                } else {
                    metadata->fields[i].typeInfo = nullptr;
                }
            }
        }
    }
}

ClassMetadata* MetadataRegistry::getClassMetadata(const std::string& className) {
    std::lock_guard<std::mutex> lock(registryMutex);
    auto it = classMetadata.find(className);
    return (it != classMetadata.end()) ? it->second : nullptr;
}

// GoroutineGCState methods
void GoroutineGCState::pushScope(void* scope) {
    // Lock to prevent race with GC thread reading scopeStack
    std::lock_guard<std::mutex> lock(scopeStackMutex);
    // Always push scopes - we need to track the current scope stack
    scopeStack.push_back(scope);
}

void GoroutineGCState::popScope() {
    // Lock to prevent race with GC thread reading scopeStack
    std::lock_guard<std::mutex> lock(scopeStackMutex);
    // Always pop scopes - we need to maintain accurate scope stack
    if (!scopeStack.empty()) {
        scopeStack.pop_back();
        
        // If we're in GC phase 2 and the stack is now smaller than the phase 2 size,
        // decrement the phase 2 size to match (scope was destroyed)
        if (isInGCPhase2 && scopeStack.size() < gcPhase2StackSize) {
            gcPhase2StackSize = scopeStack.size();
        }
    }
}

// GarbageCollector implementation
GarbageCollector::GarbageCollector() {
    std::cout << "GarbageCollector initialized with signal-based checkpointing" << std::endl;
}

GarbageCollector::~GarbageCollector() {
    stop();
}

GarbageCollector& GarbageCollector::getInstance() {
    static GarbageCollector instance;
    return instance;
}

void GarbageCollector::start() {
    if (running.load()) {
        return;
    }
    
    running.store(true);
    gcThread = std::make_unique<std::thread>(&GarbageCollector::gcThreadFunction, this);
    std::cout << "GC thread started" << std::endl;
}

void GarbageCollector::stop() {
    if (!running.load()) {
        return;
    }
    
    running.store(false);
    if (gcThread && gcThread->joinable()) {
        gcThread->join();
    }
    std::cout << "GC thread stopped" << std::endl;
}

void GarbageCollector::gcThreadFunction() {
    std::cout << "GC thread running" << std::endl;
    
    while (running.load()) {
        // Sleep for a bit before next GC cycle
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        // Run a GC cycle
        try {
            phase1_initialMarkSweep();
            
            if (!suspectedDead.empty() || !suspectedDeadScopes.empty()) {
                phase2_setFlagMonitoring();
                phase3_secondMarkSweep();
                phase4_cleanup();
            }
        } catch (const std::exception& e) {
            std::cerr << "GC cycle error: " << e.what() << std::endl;
        }
        
        // Clear state for next cycle
        suspectedDead.clear();
        suspectedDeadScopes.clear();
        objectsToFree.clear();
        scopesToFree.clear();
        markedObjects.clear();
        markedScopes.clear();
    }
    
    std::cout << "GC thread exiting" << std::endl;
}

void GarbageCollector::requestCollection() {
    // For now, just trigger immediately (could use condition variable for async)
    std::cout << "Manual GC collection requested" << std::endl;
}

std::vector<void*> GarbageCollector::collectAllAllocatedObjects() {
    std::vector<void*> allObjects;
    
    // Get all goroutines from EventLoop
    auto allGoroutines = EventLoop::getInstance().getAllGoroutines();
    
    for (auto& goroutine : allGoroutines) {
        if (goroutine && goroutine->gcState) {
            std::lock_guard<std::mutex> lock(goroutine->gcState->allocationMutex);
            allObjects.insert(allObjects.end(), 
                             goroutine->gcState->allocatedObjects.begin(),
                             goroutine->gcState->allocatedObjects.end());
        }
    }
    
    return allObjects;
}

std::vector<void*> GarbageCollector::collectAllAllocatedScopes() {
    std::vector<void*> allScopes;
    
    // Get all goroutines from EventLoop
    auto allGoroutines = EventLoop::getInstance().getAllGoroutines();
    
    for (auto& goroutine : allGoroutines) {
        if (goroutine && goroutine->gcState) {
            std::lock_guard<std::mutex> lock(goroutine->gcState->allocationMutex);
            allScopes.insert(allScopes.end(), 
                           goroutine->gcState->allocatedScopes.begin(),
                           goroutine->gcState->allocatedScopes.end());
        }
    }
    
    return allScopes;
}

std::vector<void*> GarbageCollector::collectAllRoots() {
    std::vector<void*> allRoots;
    
    // Collect scope stack from all goroutines
    // If we're in GC mode, only collect scopes that existed before phase 2
    auto allGoroutines = EventLoop::getInstance().getAllGoroutines();
    
    for (auto& goroutine : allGoroutines) {
        if (goroutine && goroutine->gcState) {
            // Lock to prevent race with pushScope/popScope modifying scopeStack
            std::lock_guard<std::mutex> lock(goroutine->gcState->scopeStackMutex);
            
            size_t limitSize = gcMode.load() ? goroutine->gcState->gcPhase2StackSize 
                                             : goroutine->gcState->scopeStack.size();
            
            for (size_t i = 0; i < limitSize && i < goroutine->gcState->scopeStack.size(); i++) {
                allRoots.push_back(goroutine->gcState->scopeStack[i]);
            }
        }
    }
    
    return allRoots;
}

void GarbageCollector::phase1_initialMarkSweep() {
    std::lock_guard<std::mutex> lock(gcMutex);
    
    // Step 1: Snapshot all allocated objects and scopes
    std::vector<void*> allObjects = collectAllAllocatedObjects();
    std::vector<void*> allScopes = collectAllAllocatedScopes();
    
    if (allObjects.empty() && allScopes.empty()) {
        return; // Nothing to collect
    }
    
    std::cout << "GC Phase 1: Mark-Sweep on " << allObjects.size() << " objects and " 
              << allScopes.size() << " scopes" << std::endl;
    
    // Step 2: Clear mark bits
    markedObjects.clear();
    markedScopes.clear();
    
    // Step 3: Mark all reachable objects from roots
    std::vector<void*> roots = collectAllRoots();
    std::cout << "  - Found " << roots.size() << " root scopes" << std::endl;
    
    for (void* root : roots) {
        if (root) {
            markScope(root);
        }
    }
    
    // Step 4: Find unreachable objects and scopes (suspected dead)
    suspectedDead.clear();
    for (void* obj : allObjects) {
        if (markedObjects.find(obj) == markedObjects.end()) {
            suspectedDead.push_back(obj);
        }
    }
    
    suspectedDeadScopes.clear();
    for (void* scope : allScopes) {
        if (markedScopes.find(scope) == markedScopes.end()) {
            suspectedDeadScopes.push_back(scope);
        }
    }
    
    std::cout << "  - Found " << suspectedDead.size() << " suspected dead objects and " 
              << suspectedDeadScopes.size() << " suspected dead scopes" << std::endl;
}

void GarbageCollector::phase2_setFlagMonitoring() {
    std::cout << "GC Phase 2: Set Flag Monitoring" << std::endl;
    
    // Mark the current scope stack size before entering GC mode
    markAllGoroutinesPhase2Start();
    
    // Enter GC mode (limits scope traversal to pre-phase-2 scopes)
    gcMode.store(true, std::memory_order_release);
    
    // For each suspected dead object, set needs_set_flag and clear set_flag
    for (void* obj : suspectedDead) {
        ObjectHeader* header = static_cast<ObjectHeader*>(obj);
        
        // Set needs_set_flag = 1, set_flag = 0 atomically
        uint64_t expected = header->flags.load(std::memory_order_acquire);
        uint64_t desired;
        do {
            desired = expected | ObjectFlags::NEEDS_SET_FLAG;
            desired &= ~ObjectFlags::SET_FLAG;
        } while (!header->flags.compare_exchange_weak(expected, desired, 
                                                       std::memory_order_release,
                                                       std::memory_order_acquire));
    }
    
    // For each suspected dead scope, set needs_set_flag and clear set_flag
    for (void* scope : suspectedDeadScopes) {
        ScopeHeader* header = static_cast<ScopeHeader*>(scope);
        
        // Set needs_set_flag = 1, set_flag = 0 atomically
        uint64_t expected = header->flags.load(std::memory_order_acquire);
        uint64_t desired;
        do {
            desired = expected | ScopeFlags::NEEDS_SET_FLAG;
            desired &= ~ScopeFlags::SET_FLAG;
        } while (!header->flags.compare_exchange_weak(expected, desired,
                                                       std::memory_order_release,
                                                       std::memory_order_acquire));
    }
    
    std::cout << "  - Monitoring " << suspectedDead.size() << " objects and " 
              << suspectedDeadScopes.size() << " scopes for resurrection" << std::endl;
    
    // Wait a bit for program to potentially create new references
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
}

void GarbageCollector::phase3_secondMarkSweep() {
    std::cout << "GC Phase 3: Second Mark-Sweep" << std::endl;
    
    // Exit GC mode and reset phase 2 markers
    gcMode.store(false, std::memory_order_release);
    resetAllGoroutinesPhase2();
    
    // STEP 1: Perform a full mark-sweep from roots to catch any new references
    // that were created during phase 2 (even those that didn't trigger the write barrier)
    std::cout << "  - Performing second mark-sweep from roots..." << std::endl;
    markedObjects.clear();
    markedScopes.clear();
    
    std::vector<void*> roots = collectAllRoots();
    for (void* root : roots) {
        if (root) {
            markScope(root);
        }
    }
    
    // STEP 2: Remove any suspected dead objects/scopes that are now reachable from roots
    std::vector<void*> stillSuspectedDead;
    std::vector<void*> stillSuspectedDeadScopes;
    
    for (void* obj : suspectedDead) {
        if (markedObjects.find(obj) != markedObjects.end()) {
            // Object was found to be reachable - it's alive!
            // (descendants already marked recursively, so they're safe too)
        } else {
            // Still not reachable from roots
            stillSuspectedDead.push_back(obj);
        }
    }
    
    for (void* scope : suspectedDeadScopes) {
        if (markedScopes.find(scope) != markedScopes.end()) {
            // Scope was found to be reachable - it's alive!
            // (descendants already marked recursively, so they're safe too)
        } else {
            // Still not reachable from roots
            stillSuspectedDeadScopes.push_back(scope);
        }
    }
    
    int objectsSavedFromRoots = suspectedDead.size() - stillSuspectedDead.size();
    int scopesSavedFromRoots = suspectedDeadScopes.size() - stillSuspectedDeadScopes.size();
    
    std::cout << "  - Saved from roots: " << objectsSavedFromRoots << " objects, " 
              << scopesSavedFromRoots << " scopes" << std::endl;
    
    // STEP 3: Iteratively check write barrier flags and mark resurrected items
    // Loop until we reach a "quiet" state where no new set_flags are found
    // This handles the case where resurrected objects create references to other
    // suspected-dead objects during the resurrection process
    
    int iteration = 0;
    bool foundNewResurrections = true;
    
    // Keep track of all items we've already resurrected across iterations
    std::set<void*> allResurrectedObjects;
    std::set<void*> allResurrectedScopes;
    
    while (foundNewResurrections) {
        iteration++;
        foundNewResurrections = false;
        
        std::cout << "  - Resurrection iteration " << iteration << std::endl;
        
        // Check flags on objects that haven't been resurrected yet
        std::vector<void*> newlyResurrected;
        for (void* obj : stillSuspectedDead) {
            // Skip if already resurrected
            if (allResurrectedObjects.find(obj) != allResurrectedObjects.end()) {
                continue;
            }
            
            ObjectHeader* header = static_cast<ObjectHeader*>(obj);
            
            // Check if set_flag was set (meaning new reference was created)
            if (header->flags.load(std::memory_order_acquire) & ObjectFlags::SET_FLAG) {
                newlyResurrected.push_back(obj);
                allResurrectedObjects.insert(obj);
                foundNewResurrections = true;
            }
        }
        
        // Check flags on scopes that haven't been resurrected yet
        std::vector<void*> newlyResurrectedScopes;
        for (void* scope : stillSuspectedDeadScopes) {
            // Skip if already resurrected
            if (allResurrectedScopes.find(scope) != allResurrectedScopes.end()) {
                continue;
            }
            
            ScopeHeader* header = static_cast<ScopeHeader*>(scope);
            
            // Check if set_flag was set (meaning new reference was created)
            if (header->flags.load(std::memory_order_acquire) & ScopeFlags::SET_FLAG) {
                newlyResurrectedScopes.push_back(scope);
                allResurrectedScopes.insert(scope);
                foundNewResurrections = true;
            }
        }
        
        if (newlyResurrected.empty() && newlyResurrectedScopes.empty()) {
            std::cout << "    - No new resurrections found (quiet state reached)" << std::endl;
            break;
        }
        
        std::cout << "    - Found " << newlyResurrected.size() << " new resurrected objects, "
                  << newlyResurrectedScopes.size() << " new resurrected scopes" << std::endl;
        
        // Mark all newly resurrected objects/scopes and their descendants
        // This will also set flags on any suspected-dead items they reference
        markedObjects.clear();
        markedScopes.clear();
        
        for (void* obj : newlyResurrected) {
            markObject(obj);
        }
        for (void* scope : newlyResurrectedScopes) {
            markScope(scope);
        }
        
        // The descendants are now marked - add them to the resurrected set
        for (void* obj : stillSuspectedDead) {
            if (markedObjects.find(obj) != markedObjects.end()) {
                allResurrectedObjects.insert(obj);
            }
        }
        for (void* scope : stillSuspectedDeadScopes) {
            if (markedScopes.find(scope) != markedScopes.end()) {
                allResurrectedScopes.insert(scope);
            }
        }
        
        // Small delay to allow any cascading write barriers to trigger
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    
    std::cout << "  - Resurrection loop complete after " << iteration << " iterations" << std::endl;
    std::cout << "  - Total resurrected: " << allResurrectedObjects.size() << " objects, "
              << allResurrectedScopes.size() << " scopes" << std::endl;
    
    // STEP 4: Final verification using signal-based memory fence
    // This ensures all goroutines have completed any pending write barrier operations
    // and all set_flag writes are globally visible
    std::cout << "  - Performing final signal-based memory fence..." << std::endl;
    ensureAllWriteBarriersComplete();
    
    // After the fence, do ONE final check for any late set_flags
    std::cout << "  - Final post-fence check for late resurrections..." << std::endl;
    int lateResurrections = 0;
    
    for (void* obj : stillSuspectedDead) {
        if (allResurrectedObjects.find(obj) != allResurrectedObjects.end()) {
            continue;
        }
        
        ObjectHeader* header = static_cast<ObjectHeader*>(obj);
        if (header->flags.load(std::memory_order_acquire) & ObjectFlags::SET_FLAG) {
            allResurrectedObjects.insert(obj);
            lateResurrections++;
            
            // Mark descendants too
            markedObjects.clear();
            markObject(obj);
            for (void* descObj : stillSuspectedDead) {
                if (markedObjects.find(descObj) != markedObjects.end()) {
                    allResurrectedObjects.insert(descObj);
                }
            }
        }
    }
    
    for (void* scope : stillSuspectedDeadScopes) {
        if (allResurrectedScopes.find(scope) != allResurrectedScopes.end()) {
            continue;
        }
        
        ScopeHeader* header = static_cast<ScopeHeader*>(scope);
        if (header->flags.load(std::memory_order_acquire) & ScopeFlags::SET_FLAG) {
            allResurrectedScopes.insert(scope);
            lateResurrections++;
            
            // Mark descendants too
            markedScopes.clear();
            markScope(scope);
            for (void* descScope : stillSuspectedDeadScopes) {
                if (markedScopes.find(descScope) != markedScopes.end()) {
                    allResurrectedScopes.insert(descScope);
                }
            }
        }
    }
    
    if (lateResurrections > 0) {
        std::cout << "    - Caught " << lateResurrections << " late resurrections after fence!" << std::endl;
    } else {
        std::cout << "    - No late resurrections (fence verification passed)" << std::endl;
    }
    
    // STEP 5: Build the final list of truly dead items (those not resurrected)
    objectsToFree.clear();
    for (void* obj : stillSuspectedDead) {
        if (allResurrectedObjects.find(obj) == allResurrectedObjects.end()) {
            objectsToFree.push_back(obj);
        }
    }
    
    scopesToFree.clear();
    for (void* scope : stillSuspectedDeadScopes) {
        if (allResurrectedScopes.find(scope) == allResurrectedScopes.end()) {
            scopesToFree.push_back(scope);
        }
    }
    
    std::cout << "  - Final truly dead to free: " << objectsToFree.size() << " objects, " 
              << scopesToFree.size() << " scopes" << std::endl;
}

void GarbageCollector::phase4_cleanup() {
    std::cout << "GC Phase 4: Cleanup" << std::endl;
    
    // Get all goroutines for cleanup
    auto allGoroutines = EventLoop::getInstance().getAllGoroutines();
    
    // Free all truly dead objects
    for (void* obj : objectsToFree) {
        ObjectHeader* header = static_cast<ObjectHeader*>(obj);
        
        // Clear flags to indicate object is being freed
        header->flags.store(0, std::memory_order_release);
        header->classMetadata = nullptr;
        
        // Remove from all goroutines' allocation lists
        for (auto& goroutine : allGoroutines) {
            if (goroutine && goroutine->gcState) {
                goroutine->gcState->removeObject(obj);
            }
        }
        
        // Free the memory
        free(obj);
    }
    
    // Free all truly dead scopes
    for (void* scope : scopesToFree) {
        ScopeHeader* header = static_cast<ScopeHeader*>(scope);
        
        // Clear flags to indicate scope is being freed
        header->flags.store(0, std::memory_order_release);
        header->scopeMetadata = nullptr;
        
        // Remove from all goroutines' allocation lists
        for (auto& goroutine : allGoroutines) {
            if (goroutine && goroutine->gcState) {
                goroutine->gcState->removeScope(scope);
            }
        }
        
        // Free the memory
        free(scope);
    }
    
    std::cout << "  - Freed " << objectsToFree.size() << " objects and " 
              << scopesToFree.size() << " scopes" << std::endl;
}

void GarbageCollector::markObject(void* obj) {
    if (!obj || markedObjects.find(obj) != markedObjects.end()) {
        return; // Already marked or null
    }
    
    markedObjects.insert(obj);
    traceObject(obj);
}

void GarbageCollector::markScope(void* scope) {
    if (!scope || markedScopes.find(scope) != markedScopes.end()) {
        return; // Already marked or null
    }
    
    markedScopes.insert(scope);
    traceScope(scope);
}

void GarbageCollector::traceObject(void* obj) {
    ObjectHeader* header = static_cast<ObjectHeader*>(obj);
    ClassMetadata* metadata = header->getClassMetadata();
    
    if (!metadata) {
        return;
    }
    
    // NOTE: With the new design, method closures are in metadata and shared
    // Instances only have POINTERS to these closures
    // We don't need to trace metadata closures since they're static and don't contain
    // per-instance data. The closure scope pointers would be filled at instantiation
    // if methods captured external scopes (currently they don't).
    
    // Trace through closure pointers in the object
    // Layout: [metadata*][flags][closure_ptr1]...[closure_ptrN][fields]
    Closure** closurePtrs = header->getClosurePtrs();
    
    // For each method closure pointer, trace the scopes it captures
    for (int i = 0; i < metadata->numMethods; i++) {
        Closure* closure = closurePtrs[i];
        if (!closure) continue;
        
        // Closure layout: [size(8)][func_addr(8)][scope_ptr1(8)][scope_ptr2(8)]...
        int numScopes = (closure->size - 16) / 8;
        
        // Trace each scope pointer in the method closure
        void** scopePtrs = closure->getScopePtrs();
        for (int j = 0; j < numScopes; j++) {
            void* scopePtr = scopePtrs[j];
            if (scopePtr) {
                markScope(scopePtr);
            }
        }
    }
    
    // Trace through object fields using metadata
    // Note: field offsets in metadata account for header + closure pointers
    uint8_t* objectStart = reinterpret_cast<uint8_t*>(obj);
    
    for (int i = 0; i < metadata->numFields; i++) {
        const VarMetadata& field = metadata->fields[i];
        
        // Check if field is an object reference
        if (field.type == DataType::OBJECT) {
            void* fieldObj = *reinterpret_cast<void**>(objectStart + field.offset);
            if (fieldObj) {
                markObject(fieldObj);
            }
        }
        // Handle closure fields - trace the scope pointers inside the closure
        else if (field.type == DataType::CLOSURE) {
            uint8_t* closurePtr = objectStart + field.offset;
            // Closure layout: [size(8)][func_addr(8)][scope_ptr1(8)][scope_ptr2(8)]...
            uint64_t closureSize = *reinterpret_cast<uint64_t*>(closurePtr);
            int numScopes = (closureSize - 16) / 8;
            
            // Trace each scope pointer in the closure
            for (int j = 0; j < numScopes; j++) {
                void* scopePtr = *reinterpret_cast<void**>(closurePtr + 16 + (j * 8));
                if (scopePtr) {
                    markScope(scopePtr);
                }
            }
        }
    }
}

void GarbageCollector::traceScope(void* scope) {
    ScopeHeader* header = static_cast<ScopeHeader*>(scope);
    ScopeMetadata* metadata = header->getScopeMetadata();
    
    if (!metadata) {
        return; // No metadata, nothing to trace
    }
    
    // Trace through scope variables using metadata
    uint8_t* dataStart = header->getDataStart();
    
    for (int i = 0; i < metadata->numVars; i++) {
        const VarMetadata& var = metadata->vars[i];
        
        // Check if variable is an object reference
        if (var.type == DataType::OBJECT) {
            void* varObj = *reinterpret_cast<void**>(dataStart + var.offset);
            if (varObj) {
                markObject(varObj);
            }
        }
        // Handle closure variables - trace the scope pointers inside the closure
        else if (var.type == DataType::CLOSURE) {
            uint8_t* closurePtr = dataStart + var.offset;
            // Closure layout: [func_addr(8)][size(8)][scope_ptr1(8)][scope_ptr2(8)]...
            uint64_t closureSize = *reinterpret_cast<uint64_t*>(closurePtr + 8);
            int numScopes = (closureSize - 16) / 8;
            
            // Trace each scope pointer in the closure
            for (int j = 0; j < numScopes; j++) {
                void* scopePtr = *reinterpret_cast<void**>(closurePtr + 16 + (j * 8));
                if (scopePtr) {
                    markScope(scopePtr);
                }
            }
        }
    }
}

void GarbageCollector::markAllGoroutinesPhase2Start() {
    // Mark the current scope stack size for all goroutines
    auto allGoroutines = EventLoop::getInstance().getAllGoroutines();
    
    for (auto& goroutine : allGoroutines) {
        if (goroutine && goroutine->gcState) {
            goroutine->gcState->markGCPhase2Start();
        }
    }
    
    std::cout << "  - Marked phase 2 start for " << allGoroutines.size() << " goroutines" << std::endl;
}

void GarbageCollector::resetAllGoroutinesPhase2() {
    // Reset phase 2 markers for all goroutines
    auto allGoroutines = EventLoop::getInstance().getAllGoroutines();
    
    for (auto& goroutine : allGoroutines) {
        if (goroutine && goroutine->gcState) {
            goroutine->gcState->resetGCPhase2();
        }
    }
    
    std::cout << "  - Reset phase 2 for " << allGoroutines.size() << " goroutines" << std::endl;
}

void GarbageCollector::ensureAllWriteBarriersComplete() {
    auto allGoroutines = EventLoop::getInstance().getAllGoroutines();
    
    if (allGoroutines.empty()) {
        return; // No goroutines to fence
    }
    
    std::cout << "  - Initiating signal-based memory fence for " << allGoroutines.size() 
              << " goroutines..." << std::endl;
    
    // Step 1: Record current checkpoint values for each goroutine
    std::vector<uint64_t> initialCheckpoints;
    initialCheckpoints.reserve(allGoroutines.size());
    
    for (auto& g : allGoroutines) {
        if (g && g->gcState) {
            initialCheckpoints.push_back(
                g->gcState->checkpointCounter.load(std::memory_order_acquire)
            );
        } else {
            initialCheckpoints.push_back(0); // No gcState - will skip
        }
    }
    
    // Step 2: Send SIGUSR1 to all goroutine threads
    // This interrupts each thread and forces it to execute the signal handler
    // The signal handler creates a memory fence and increments checkpointCounter
    for (auto& g : allGoroutines) {
        if (g && g->gcState) {
            int result = pthread_kill(g->gcState->threadId, SIGUSR1);
            if (result != 0) {
                std::cerr << "    - Warning: Failed to send signal to goroutine (error " 
                         << result << ")" << std::endl;
            }
        }
    }
    
    // Step 3: Wait for all goroutines to acknowledge by changing their counters
    // We check if the value is DIFFERENT (not specifically +1) to handle wraparound
    // Use a timeout to avoid hanging forever if a goroutine is stuck
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
    bool allAcknowledged = false;
    int checkCount = 0;
    
    while (!allAcknowledged && std::chrono::steady_clock::now() < deadline) {
        allAcknowledged = true;
        checkCount++;
        
        for (size_t i = 0; i < allGoroutines.size(); i++) {
            auto& g = allGoroutines[i];
            if (g && g->gcState) {
                uint64_t current = g->gcState->checkpointCounter.load(
                    std::memory_order_acquire
                );
                
                // Check if counter has changed (signal handler ran)
                // This handles wraparound correctly - we just care that it's different
                if (current == initialCheckpoints[i]) {
                    allAcknowledged = false;
                    break; // Still waiting for this goroutine
                }
            }
        }
        
        if (!allAcknowledged) {
            // Brief sleep before checking again
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
    }
    
    if (allAcknowledged) {
        std::cout << "    - All goroutines reached checkpoint (checked " << checkCount 
                  << " times)" << std::endl;
        std::cout << "    - Memory fence complete: all write barriers are globally visible" 
                  << std::endl;
    } else {
        std::cerr << "    - Warning: Timeout waiting for goroutines to reach checkpoint" 
                  << std::endl;
        std::cerr << "    - Some goroutines may not have completed write barriers" 
                  << std::endl;
        
        // Log which goroutines didn't respond
        for (size_t i = 0; i < allGoroutines.size(); i++) {
            auto& g = allGoroutines[i];
            if (g && g->gcState) {
                uint64_t current = g->gcState->checkpointCounter.load(
                    std::memory_order_acquire
                );
                if (current == initialCheckpoints[i]) {
                    std::cerr << "      - Goroutine " << i << " did not respond" << std::endl;
                }
            }
        }
    }
}

// Runtime functions
extern "C" {
    void gc_track_object(void* obj) {
        if (!obj) return;
        
        if (currentTask && currentTask->gcState) {
            currentTask->gcState->addObject(obj);
        }
    }
    
    void gc_track_scope(void* scope) {
        if (!scope) return;
        
        if (currentTask && currentTask->gcState) {
            currentTask->gcState->addScope(scope);
        }
    }
    
    void gc_push_scope(void* scope) {
        if (!scope) return;
        
        if (currentTask && currentTask->gcState) {
            currentTask->gcState->pushScope(scope);
        }
    }
    
    void gc_pop_scope() {
        if (currentTask && currentTask->gcState) {
            currentTask->gcState->popScope();
        }
    }
    
    // NOTE: gc_handle_assignment and gc_handle_scope_assignment are now inlined
    // directly in the generated assembly code for better performance.
    // The inline version does:
    //   1. Load flags from object header
    //   2. Test if NEEDS_SET_FLAG is set
    //   3. If set, atomically OR the SET_FLAG bit using LOCK OR instruction
    // This avoids the function call overhead while maintaining thread safety.
    
    /*
    void gc_handle_assignment(void* targetObj) {
        if (!targetObj) return;
        
        ObjectHeader* header = static_cast<ObjectHeader*>(targetObj);
        
        // Check if needs_set_flag is set
        uint64_t flags = header->flags.load(std::memory_order_acquire);
        if (flags & ObjectFlags::NEEDS_SET_FLAG) {
            // Set the set_flag to indicate a new reference was created
            header->flags.fetch_or(ObjectFlags::SET_FLAG, std::memory_order_release);
        }
    }
    
    void gc_handle_scope_assignment(void* targetScope) {
        if (!targetScope) return;
        
        ScopeHeader* header = static_cast<ScopeHeader*>(targetScope);
        
        // Check if needs_set_flag is set
        uint64_t flags = header->flags.load(std::memory_order_acquire);
        if (flags & ScopeFlags::NEEDS_SET_FLAG) {
            // Set the set_flag to indicate a new reference was created
            header->flags.fetch_or(ScopeFlags::SET_FLAG, std::memory_order_release);
        }
    }
    */
    
    void gc_collect() {
        GarbageCollector::getInstance().requestCollection();
    }
}
