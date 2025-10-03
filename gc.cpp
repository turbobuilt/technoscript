#include "gc.h"
#include "goroutine.h"
#include "ast.h"
#include <iostream>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <map>

// Thread-local current goroutine (defined in goroutine.cpp)
extern thread_local std::shared_ptr<Goroutine> currentTask;

// MetadataRegistry implementation
MetadataRegistry& MetadataRegistry::getInstance() {
    static MetadataRegistry instance;
    return instance;
}

MetadataRegistry::~MetadataRegistry() {
    // Clean up all allocated metadata
    for (auto& [name, metadata] : classMetadata) {
        if (metadata) {
            delete[] metadata->fields;
            delete metadata;
        }
    }
}

void MetadataRegistry::buildClassMetadata(const std::map<std::string, ClassDeclNode*>& classRegistry) {
    std::lock_guard<std::mutex> lock(registryMutex);
    
    std::cout << "Building class metadata for " << classRegistry.size() << " classes" << std::endl;
    
    for (const auto& [className, classDecl] : classRegistry) {
        // Count fields that need GC tracking (objects and closures)
        std::vector<VarMetadata> trackedFields;
        
        for (const auto& [fieldName, fieldInfo] : classDecl->fields) {
            if (fieldInfo.type == DataType::OBJECT || fieldInfo.type == DataType::CLOSURE) {
                void* typeInfo = nullptr;
                
                // For objects, we'll set typeInfo to point to the class metadata
                // This will be resolved in a second pass
                if (fieldInfo.type == DataType::OBJECT && fieldInfo.classNode) {
                    typeInfo = fieldInfo.classNode; // Temporary: store ClassDeclNode, will resolve later
                }
                
                trackedFields.emplace_back(fieldInfo.offset, fieldInfo.type, typeInfo);
            }
        }
        
        // Allocate and populate metadata
        ClassMetadata* metadata = new ClassMetadata();
        metadata->className = classDecl->className.c_str();
        metadata->numFields = trackedFields.size();
        metadata->totalSize = classDecl->totalSize;
        
        if (metadata->numFields > 0) {
            metadata->fields = new VarMetadata[metadata->numFields];
            for (int i = 0; i < metadata->numFields; i++) {
                metadata->fields[i] = trackedFields[i];
            }
        } else {
            metadata->fields = nullptr;
        }
        
        classMetadata[className] = metadata;
        std::cout << "  - Created metadata for class '" << className << "' with " 
                  << metadata->numFields << " tracked fields" << std::endl;
    }
    
    // Second pass: resolve ClassDeclNode pointers to ClassMetadata pointers
    for (auto& [className, metadata] : classMetadata) {
        for (int i = 0; i < metadata->numFields; i++) {
            if (metadata->fields[i].type == DataType::OBJECT && metadata->fields[i].typeInfo) {
                // typeInfo currently points to ClassDeclNode, resolve to ClassMetadata
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
    // Always push scopes - we need to track the current scope stack
    scopeStack.push_back(scope);
}

void GoroutineGCState::popScope() {
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
    std::cout << "GarbageCollector initialized" << std::endl;
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
            
            if (!suspectedDead.empty()) {
                phase2_setFlagMonitoring();
                phase3_secondMarkSweep();
                phase4_cleanup();
            }
        } catch (const std::exception& e) {
            std::cerr << "GC cycle error: " << e.what() << std::endl;
        }
        
        // Clear state for next cycle
        suspectedDead.clear();
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

std::vector<void*> GarbageCollector::collectAllRoots() {
    std::vector<void*> allRoots;
    
    // Collect scope stack from all goroutines
    // If we're in GC mode, only collect scopes that existed before phase 2
    auto allGoroutines = EventLoop::getInstance().getAllGoroutines();
    
    for (auto& goroutine : allGoroutines) {
        if (goroutine && goroutine->gcState) {
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
    
    // Step 1: Snapshot all allocated objects
    std::vector<void*> allObjects = collectAllAllocatedObjects();
    
    if (allObjects.empty()) {
        return; // Nothing to collect
    }
    
    std::cout << "GC Phase 1: Mark-Sweep on " << allObjects.size() << " objects" << std::endl;
    
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
    
    // Step 4: Find unreachable objects (suspected dead)
    suspectedDead.clear();
    for (void* obj : allObjects) {
        if (markedObjects.find(obj) == markedObjects.end()) {
            suspectedDead.push_back(obj);
        }
    }
    
    std::cout << "  - Found " << suspectedDead.size() << " suspected dead objects" << std::endl;
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
        
        // Set needs_set_flag = 1, set_flag = 0
        uint64_t flags = header->flags;
        flags |= ObjectFlags::NEEDS_SET_FLAG;
        flags &= ~ObjectFlags::SET_FLAG;
        header->flags = flags;
    }
    
    // Memory fence to ensure visibility
    std::atomic_thread_fence(std::memory_order_seq_cst);
    
    std::cout << "  - Monitoring " << suspectedDead.size() << " objects for resurrection" << std::endl;
    
    // Wait a bit for program to potentially create new references
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
}

void GarbageCollector::phase3_secondMarkSweep() {
    std::cout << "GC Phase 3: Second Mark-Sweep" << std::endl;
    
    // Memory fence to read latest set_flag values
    std::atomic_thread_fence(std::memory_order_seq_cst);
    
    // Exit GC mode and reset phase 2 markers
    gcMode.store(false, std::memory_order_release);
    resetAllGoroutinesPhase2();
    
    // Check each suspected dead object
    std::vector<void*> resurrected;
    std::vector<void*> trulyDead;
    
    for (void* obj : suspectedDead) {
        ObjectHeader* header = static_cast<ObjectHeader*>(obj);
        
        // Check if set_flag was set (meaning new reference was created)
        if (header->flags & ObjectFlags::SET_FLAG) {
            resurrected.push_back(obj);
        } else {
            trulyDead.push_back(obj);
        }
    }
    
    std::cout << "  - Resurrected: " << resurrected.size() << ", Truly dead: " << trulyDead.size() << std::endl;
    
    // For resurrected objects, mark them and their descendants as live
    markedObjects.clear();
    for (void* obj : resurrected) {
        markObject(obj);
    }
    
    // Remove resurrected objects from suspected dead
    suspectedDead = trulyDead;
}

void GarbageCollector::phase4_cleanup() {
    std::cout << "GC Phase 4: Cleanup" << std::endl;
    
    // Get all goroutines for cleanup
    auto allGoroutines = EventLoop::getInstance().getAllGoroutines();
    
    // Free all truly dead objects
    for (void* obj : suspectedDead) {
        ObjectHeader* header = static_cast<ObjectHeader*>(obj);
        
        // Clear flags to indicate object is being freed
        header->flags = 0;
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
    
    std::cout << "  - Freed " << suspectedDead.size() << " objects" << std::endl;
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
    
    // Trace through object fields using metadata
    uint8_t* fieldStart = header->getFieldsStart();
    
    for (int i = 0; i < metadata->numFields; i++) {
        const VarMetadata& field = metadata->fields[i];
        
        // Check if field is an object reference
        if (field.type == DataType::OBJECT) {
            void* fieldObj = *reinterpret_cast<void**>(fieldStart + field.offset);
            if (fieldObj) {
                markObject(fieldObj);
            }
        }
        // Handle closure fields - trace the scope pointers inside the closure
        else if (field.type == DataType::CLOSURE) {
            uint8_t* closurePtr = fieldStart + field.offset;
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

// Runtime functions
extern "C" {
    void gc_track_object(void* obj) {
        if (!obj) return;
        
        if (currentTask && currentTask->gcState) {
            currentTask->gcState->addObject(obj);
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
    
    void gc_handle_assignment(void* targetObj) {
        if (!targetObj) return;
        
        ObjectHeader* header = static_cast<ObjectHeader*>(targetObj);
        
        // Check if needs_set_flag is set
        if (header->flags & ObjectFlags::NEEDS_SET_FLAG) {
            // Set the set_flag to indicate a new reference was created
            header->flags |= ObjectFlags::SET_FLAG;
            
            // Memory fence to ensure visibility
            std::atomic_thread_fence(std::memory_order_release);
        }
    }
    
    void gc_collect() {
        GarbageCollector::getInstance().requestCollection();
    }
}
