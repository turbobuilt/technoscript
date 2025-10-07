#ifndef V8_V8_ISOLATE_H_
#define V8_V8_ISOLATE_H_

#include <cstddef>

namespace v8 {

// Forward declarations
template <typename T> class Local;
template <typename T> class MaybeLocal;
class Context;
class Value;
class String;

/**
 * Isolate represents an isolated instance of the V8 engine.
 * Each isolate has its own heap and cannot share objects with other isolates.
 */
class Isolate {
public:
    /**
     * Initial configuration parameters for a new Isolate.
     */
    struct CreateParams {
        CreateParams() : array_buffer_allocator(nullptr) {}
        
        /**
         * The optional entry_hook allows user-defined code to be executed on 
         * function entry.
         */
        void* entry_hook = nullptr;
        
        /**
         * ResourceConstraints to use for the new Isolate.
         */
        void* constraints = nullptr;
        
        /**
         * The ArrayBuffer::Allocator to use for allocating and freeing the backing
         * store of ArrayBuffers.
         */
        void* array_buffer_allocator;
    };
    
    /**
     * Creates a new isolate. Does not change the currently entered isolate.
     *
     * When an isolate is no longer used its resources should be freed
     * by calling Dispose(). Using the delete operator is not allowed.
     */
    static Isolate* New(const CreateParams& params);
    
    /**
     * Disposes the isolate. The isolate must not be entered by any
     * thread to be disposable.
     */
    void Dispose();
    
    /**
     * Associate embedder-specific data with the isolate.
     */
    void SetData(uint32_t slot, void* data);
    
    /**
     * Retrieve embedder-specific data from the isolate.
     */
    void* GetData(uint32_t slot);
    
    /**
     * Returns the isolate inside which the current thread is running.
     */
    static Isolate* GetCurrent();
    
    /**
     * Methods for entering/exiting the isolate.
     */
    void Enter();
    void Exit();
    
    /**
     * Returns true if this isolate has a current context.
     */
    bool InContext();
    
    /**
     * Returns the context that is on the top of the stack.
     */
    Local<Context> GetCurrentContext();
    
    /**
     * Request garbage collection in this isolate.
     */
    void RequestGarbageCollectionForTesting();
    
    /**
     * Get statistics about the heap memory usage.
     */
    void GetHeapStatistics(void* heap_statistics);
    
private:
    Isolate();
    ~Isolate();
    Isolate(const Isolate&) = delete;
    Isolate& operator=(const Isolate&) = delete;
    
    // Internal implementation pointer
    void* internal_isolate_;
    void* embedder_data_[4];
};

}  // namespace v8

#endif  // V8_V8_ISOLATE_H_
