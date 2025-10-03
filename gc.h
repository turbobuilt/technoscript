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
    
    VarMetadata(int o = 0, DataType t = DataType::INT64, void* ti = nullptr)
        : offset(o), type(t), typeInfo(ti) {}
};

struct ScopeMetadata {
    int numVars;              // Number of variables in this scope
    VarMetadata* vars;        // Array of variable metadata
    
    ScopeMetadata(int n = 0, VarMetadata* v = nullptr) : numVars(n), vars(v) {}
};

struct ClassMetadata {
    const char* className;    // Name of the class
    int numFields;            // Number of fields
    VarMetadata* fields;      // Array of field metadata
    int totalSize;            // Total size of object (including header)
    
    ClassMetadata(const char* name = nullptr, int n = 0, VarMetadata* f = nullptr, int size = 0)
        : className(name), numFields(n), fields(f), totalSize(size) {}
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
    constexpr uint64_t GC_MARKED = 1ULL << 0;       // Bit 0: Marked as reachable during GC
}

// Object header structure (must match ObjectLayout in codegen.h)
struct ObjectHeader {
    uint64_t flags;           // Offset 0: GC flags
    void* classMetadata;      // Offset 8: Pointer to ClassMetadata (was classRef)
    void* dynamicVars;        // Offset 16: Dynamic variables (unused for now)
    // Fields start at offset 24
    
    ClassMetadata* getClassMetadata() const { 
        return static_cast<ClassMetadata*>(classMetadata); 
    }
    
    // Legacy compatibility - will be removed once codegen is updated
    ClassDeclNode* getClassDecl() const { 
        return static_cast<ClassDeclNode*>(classMetadata); 
    }
    
    uint8_t* getFieldsStart() { 
        return reinterpret_cast<uint8_t*>(this) + 24; 
    }
};

// Scope header structure (must match ScopeLayout in codegen.h)
struct ScopeHeader {
    uint64_t flags;           // Offset 0: GC flags
    void* scopeMetadata;      // Offset 8: Pointer to ScopeMetadata
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
    std::vector<void*> scopeStack;        // Stack of active lexical scopes (roots)
    std::mutex allocationMutex;           // Protects allocatedObjects list
    size_t gcPhase2StackSize = 0;         // Size of scope stack when phase 2 started
    bool isInGCPhase2 = false;            // True when in GC phase 2
    
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
    
    // Push scope to stack (called when entering a scope)
    void pushScope(void* scope);
    
    // Pop scope from stack (called when exiting a scope)
    void popScope();
    
    // Mark the current stack size at start of GC phase 2
    void markGCPhase2Start() {
        gcPhase2StackSize = scopeStack.size();
        isInGCPhase2 = true;
    }
    
    // Reset after GC phase 2
    void resetGCPhase2() {
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
    std::vector<void*> suspectedDead;
    std::unordered_set<void*> markedObjects;
    std::unordered_set<void*> markedScopes;
    
    // GC algorithm phases
    void phase1_initialMarkSweep();
    void phase2_setFlagMonitoring();
    void phase3_secondMarkSweep();
    void phase4_cleanup();
    
    // Mark all goroutines for phase 2 start
    void markAllGoroutinesPhase2Start();
    void resetAllGoroutinesPhase2();
    
    // Helper methods
    void markObject(void* obj);
    void markScope(void* scope);
    void traceObject(void* obj);
    void traceScope(void* scope);
    std::vector<void*> collectAllAllocatedObjects();
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
    
    // Push/Pop scope from GC roots (called on scope entry/exit)
    void gc_push_scope(void* scope);
    void gc_pop_scope();
    
    // Handle object assignment (checks set flags)
    void gc_handle_assignment(void* targetObj);
    
    // Manual GC trigger
    void gc_collect();
}
