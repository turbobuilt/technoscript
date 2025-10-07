#pragma once

#include "ast.h"  // For DataType enum and forward declarations
#include <cstdint>
#include <vector>
#include <unordered_set>
#include <atomic>
#include <thread>
#include <mutex>
#include <algorithm>
#include <map>

// Forward declarations
class Goroutine;

// Runtime metadata structures (AOT-compatible)
struct VarMetadata {
    int offset;               // Offset within scope/object data area
    DataType type;            // Type of the variable/field
    void* typeInfo;           // For OBJECT: points to ClassMetadata, nullptr otherwise
    const char* name;         // Field/var name (for dynamic access like obj["fieldName"])
    
    VarMetadata(int o = 0, DataType t = DataType::INT64, void* ti = nullptr, const char* n = nullptr)
        : offset(o), type(t), typeInfo(ti), name(n) {}
};

struct ScopeMetadata {
    int numVars;              // Number of variables in this scope
    VarMetadata* vars;        // Array of variable metadata
    
    ScopeMetadata(int n = 0, VarMetadata* v = nullptr) : numVars(n), vars(v) {}
};

// Closure structure embedded in metadata
// Layout: [size(8)][func_addr(8)][scope_ptr1(8)]...[scope_ptrN(8)]
// Note: Size is first so the closure itself knows its size
struct Closure {
    size_t size;           // Total size of this closure including size field
    void* funcAddr;        // Function address
    // Followed by N scope pointers (variable number)
    
    void** getScopePtrs() {
        return reinterpret_cast<void**>(reinterpret_cast<uint8_t*>(this) + 16);
    }
};

struct ClassMetadata {
    const char* className;    // Name of the class
    int numFields;            // Number of fields
    VarMetadata* fields;      // Array of field metadata (includes inherited fields)
    int totalSize;            // Total size of object fields (NOT including header)
    
    // Method closures - simple array of closure pointers (one per method)
    // Each instance copies these pointers, so all instances share the same closures
    int numMethods;           // Number of methods
    Closure** methodClosures; // Array of pointers to method closures
    
    // Parent class information for multiple inheritance
    int numParents;           // Number of parent classes
    const char** parentNames; // Array of parent class names
    int* parentOffsets;       // Array of offsets to parent data in object layout
    
    ClassMetadata(const char* name = nullptr, int nf = 0, VarMetadata* f = nullptr, int size = 0,
                  int nm = 0, Closure** mc = nullptr,
                  int np = 0, const char** pn = nullptr, int* po = nullptr)
        : className(name), numFields(nf), fields(f), totalSize(size),
          numMethods(nm), methodClosures(mc),
          numParents(np), parentNames(pn), parentOffsets(po) {}
};

// Global class metadata registry
class MetadataRegistry {
private:
    std::map<std::string, ClassMetadata*> classMetadata;
    std::mutex registryMutex;
    
public:
    // Build class metadata from AST class registry (called after parsing/analysis)
    void buildClassMetadata(const std::map<std::string, ClassDeclNode*>& classRegistry);
    
    // Get class metadata by name
    ClassMetadata* getClassMetadata(const std::string& className);
    
    // Singleton access
    static MetadataRegistry& getInstance();
    
    ~MetadataRegistry();
};

// Object header flags (bit positions in the FLAGS field at offset 0)
namespace ObjectFlags {
    constexpr uint64_t NEEDS_SET_FLAG = 1ULL << 0;  // Bit 0: Object is suspected dead, track new refs
    constexpr uint64_t SET_FLAG = 1ULL << 1;        // Bit 1: New reference was created during GC
    constexpr uint64_t GC_MARKED = 1ULL << 2;       // Bit 2: Marked as reachable during GC
}

// Scope header flags (bit positions in the FLAGS field at offset 0)
namespace ScopeFlags {
    constexpr uint64_t NEEDS_SET_FLAG = 1ULL << 0;  // Bit 0: Scope is suspected dead, track new refs
    constexpr uint64_t SET_FLAG = 1ULL << 1;        // Bit 1: New reference was created during GC
    constexpr uint64_t GC_MARKED = 1ULL << 2;       // Bit 2: Marked as reachable during GC
}

// Object header structure (must match ObjectLayout in codegen.h)
// Layout: [classMetadata*][flags][closure_ptr1]...[closure_ptrN][fields...]
// NOTE: Instances have POINTERS to closures (8 bytes each), which point to closures in ClassMetadata
struct ObjectHeader {
    void* classMetadata;          // Offset 0: Pointer to ClassMetadata (includes vtable)
    std::atomic<uint64_t> flags;  // Offset 8: GC flags (atomic for thread safety)
    // Closure pointers start at offset 16 (one 8-byte pointer per method)
    // Fields start after closure pointers (offset = 16 + numMethods * 8)
    
    ClassMetadata* getClassMetadata() const { 
        return static_cast<ClassMetadata*>(classMetadata); 
    }
    
    // Get pointer to closure pointer array (starts at offset 16)
    Closure** getClosurePtrs() { 
        return reinterpret_cast<Closure**>(reinterpret_cast<uint8_t*>(this) + 16); 
    }
    
    // Get closure pointer for a specific method index
    Closure* getMethodClosure(int methodIndex) {
        Closure** ptrs = getClosurePtrs();
        return ptrs[methodIndex];
    }
    
    // Set closure pointer for a specific method index
    void setMethodClosure(int methodIndex, Closure* closure) {
        Closure** ptrs = getClosurePtrs();
        ptrs[methodIndex] = closure;
    }
};

// Scope header structure (must match ScopeLayout in codegen.h)
struct ScopeHeader {
    std::atomic<uint64_t> flags;  // Offset 0: GC flags (atomic for thread safety)
    void* scopeMetadata;          // Offset 8: Pointer to ScopeMetadata
    // Variables/parameters start at offset 16 (was 8)
    
    ScopeMetadata* getScopeMetadata() const {
        return static_cast<ScopeMetadata*>(scopeMetadata);
    }
    
    uint8_t* getDataStart() {
        return reinterpret_cast<uint8_t*>(this) + 16;  // Changed from 8
    }
};

// Per-goroutine GC state
struct GoroutineGCState {
    std::vector<void*> allocatedObjects;  // All objects allocated by this goroutine
    std::vector<void*> allocatedScopes;   // All scopes allocated by this goroutine
    std::vector<void*> scopeStack;        // Stack of active lexical scopes (roots)
    std::mutex allocationMutex;           // Protects allocatedObjects and allocatedScopes lists
    std::mutex scopeStackMutex;           // Protects scopeStack and phase2 tracking variables
    size_t gcPhase2StackSize = 0;         // Size of scope stack when phase 2 started
    bool isInGCPhase2 = false;            // True when in GC phase 2
    
    // Signal-based memory fence support
    std::atomic<uint64_t> checkpointCounter{0};  // Incremented when signal handler runs
    pthread_t threadId;                           // Thread ID for sending signals
    
    void addObject(void* obj) {
        std::lock_guard<std::mutex> lock(allocationMutex);
        allocatedObjects.push_back(obj);
    }
    
    void removeObject(void* obj) {
        std::lock_guard<std::mutex> lock(allocationMutex);
        auto it = std::find(allocatedObjects.begin(), allocatedObjects.end(), obj);
        if (it != allocatedObjects.end()) {
            allocatedObjects.erase(it);
        }
    }
    
    void addScope(void* scope) {
        std::lock_guard<std::mutex> lock(allocationMutex);
        allocatedScopes.push_back(scope);
    }
    
    void removeScope(void* scope) {
        std::lock_guard<std::mutex> lock(allocationMutex);
        auto it = std::find(allocatedScopes.begin(), allocatedScopes.end(), scope);
        if (it != allocatedScopes.end()) {
            allocatedScopes.erase(it);
        }
    }
    
    // Push scope to stack (called when entering a scope)
    void pushScope(void* scope);
    
    // Pop scope from stack (called when exiting a scope)
    void popScope();
    
    // Mark the current stack size at start of GC phase 2
    void markGCPhase2Start() {
        std::lock_guard<std::mutex> lock(scopeStackMutex);
        gcPhase2StackSize = scopeStack.size();
        isInGCPhase2 = true;
    }
    
    // Reset after GC phase 2
    void resetGCPhase2() {
        std::lock_guard<std::mutex> lock(scopeStackMutex);
        gcPhase2StackSize = 0;
        isInGCPhase2 = false;
    }
};

// Main garbage collector
class GarbageCollector {
private:
    std::atomic<bool> running{false};
    std::atomic<bool> gcMode{false};  // Set during phase 2 to ignore scope push/pop
    std::unique_ptr<std::thread> gcThread;
    std::mutex gcMutex;
    
    // GC cycle state
    std::vector<void*> suspectedDead;      // Objects suspected dead after phase 1
    std::vector<void*> suspectedDeadScopes; // Scopes suspected dead after phase 1
    std::vector<void*> objectsToFree;      // Final list of truly dead objects to free in phase 4
    std::vector<void*> scopesToFree;       // Final list of truly dead scopes to free in phase 4
    std::unordered_set<void*> markedObjects;
    std::unordered_set<void*> markedScopes;
    
    // GC algorithm phases
    void phase1_initialMarkSweep();
    void phase2_setFlagMonitoring();
    void phase3_secondMarkSweep();
    void phase4_cleanup();
    
    // Signal-based memory fence to ensure all write barriers complete
    void ensureAllWriteBarriersComplete();
    
    // Mark all goroutines for phase 2 start
    void markAllGoroutinesPhase2Start();
    void resetAllGoroutinesPhase2();
    
    // Helper methods
    void markObject(void* obj);
    void markScope(void* scope);
    void traceObject(void* obj);
    void traceScope(void* scope);
    std::vector<void*> collectAllAllocatedObjects();
    std::vector<void*> collectAllAllocatedScopes();
    std::vector<void*> collectAllRoots();
    
    // Main GC loop
    void gcThreadFunction();
    
public:
    GarbageCollector();
    ~GarbageCollector();
    
    void start();
    void stop();
    void requestCollection();  // Request a GC cycle
    
    bool isGCMode() const { return gcMode.load(std::memory_order_acquire); }
    
    // Singleton access
    static GarbageCollector& getInstance();
};

// Runtime functions callable from generated code
extern "C" {
    // Track object allocation (called after malloc in generated code)
    void gc_track_object(void* obj);
    
    // Track scope allocation (called after scope allocation in generated code)
    void gc_track_scope(void* scope);
    
    // Push/Pop scope from GC roots (called on scope entry/exit)
    void gc_push_scope(void* scope);
    void gc_pop_scope();
    
    // NOTE: gc_handle_assignment and gc_handle_scope_assignment are now inlined
    // directly in generated assembly code for performance. See codegen.cpp.
    // void gc_handle_assignment(void* targetObj);
    // void gc_handle_scope_assignment(void* targetScope);
    
    // Manual GC trigger
    void gc_collect();
}
