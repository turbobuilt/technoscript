#ifndef V8_V8_HANDLE_SCOPE_H_
#define V8_V8_HANDLE_SCOPE_H_

#include "v8-local-handle.h"

namespace v8 {

class Isolate;

/**
 * A stack-allocated class that governs a number of local handles.
 * After a handle scope has been created, all local handles will be
 * allocated within that handle scope until either the handle scope is
 * deleted or another handle scope is created.  If there is already a
 * handle scope and a new one is created, all allocations will take
 * place in the new handle scope until it is deleted.  After that,
 * new handles will again be allocated in the original handle scope.
 *
 * After the handle scope of a local handle has been deleted the
 * garbage collector will no longer track the object stored in the
 * handle and may deallocate it.  The behavior of accessing a handle
 * for which the handle scope has been deleted is undefined.
 */
class HandleScope {
public:
    explicit HandleScope(Isolate* isolate);
    ~HandleScope();
    
    /**
     * Counts the number of allocated handles.
     */
    static int NumberOfHandles(Isolate* isolate);
    
    /**
     * Returns the isolate associated with this handle scope.
     */
    Isolate* GetIsolate() const;
    
protected:
    HandleScope() = default;
    
    void Initialize(Isolate* isolate);
    
    // Internal implementation data
    void* internal_[4];
    
private:
    // Prevent copying
    HandleScope(const HandleScope&) = delete;
    HandleScope& operator=(const HandleScope&) = delete;
};

/**
 * A HandleScope which first allocates a handle in the current scope
 * which will be later filled with the escape value.
 */
class EscapableHandleScope : public HandleScope {
public:
    explicit EscapableHandleScope(Isolate* isolate);
    ~EscapableHandleScope() = default;
    
    /**
     * Pushes the value into the previous scope and returns a handle to it.
     * Cannot be called twice.
     */
    template <typename T>
    Local<T> Escape(Local<T> value) {
        // In a real implementation, this would move the handle to the outer scope
        return value;
    }
    
private:
    bool escape_called_;
    
    EscapableHandleScope(const EscapableHandleScope&) = delete;
    EscapableHandleScope& operator=(const EscapableHandleScope&) = delete;
};

/**
 * A HandleScope that seals the current HandleScope and prevents
 * the creation of new handles in that scope.
 */
class SealHandleScope {
public:
    explicit SealHandleScope(Isolate* isolate);
    ~SealHandleScope();
    
private:
    void* internal_[2];
    
    SealHandleScope(const SealHandleScope&) = delete;
    SealHandleScope& operator=(const SealHandleScope&) = delete;
};

}  // namespace v8

#endif  // V8_V8_HANDLE_SCOPE_H_
