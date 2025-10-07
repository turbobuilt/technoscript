#ifndef V8_V8_LOCAL_HANDLE_H_
#define V8_V8_LOCAL_HANDLE_H_

#include "v8-internal.h"
#include <cstddef>

namespace v8 {

// Forward declarations
class Isolate;
template <typename T> class Persistent;
template <typename T> class Eternal;

/**
 * An object reference managed by the v8 garbage collector.
 *
 * All objects returned from v8 have to be tracked by the garbage
 * collector so that it knows that the objects are still alive.  Also,
 * because the garbage collector may move objects, it is unsafe to
 * point directly to an object.  Instead, all objects are stored in
 * handles which are known by the garbage collector and updated
 * whenever an object moves.  Handles should always be passed by value
 * (except in cases like out-parameters) and they should never be
 * allocated on the heap.
 *
 * There are two types of handles: local and persistent handles.
 *
 * Local handles are light-weight and transient and typically used in
 * local operations.  They are managed by HandleScopes. That means that a
 * HandleScope must exist on the stack when they are created and that they are
 * only valid inside of the HandleScope active during their creation.
 * For passing a local handle to an outer HandleScope, an
 * EscapableHandleScope and its Escape() method must be used.
 *
 * Persistent handles can be used when storing objects across several
 * independent operations and have to be explicitly deallocated when they're no
 * longer used.
 */
template <typename T>
class Local {
public:
    Local() : val_(nullptr) {}
    
    /**
     * Creates a Local from another Local.
     */
    template <typename S>
    Local(Local<S> that) : val_(reinterpret_cast<T*>(*that)) {
        // Type checking would go here in full implementation
    }
    
    /**
     * Returns true if the handle is empty.
     */
    bool IsEmpty() const { return val_ == nullptr; }
    
    /**
     * Sets the handle to be empty. IsEmpty() will then return true.
     */
    void Clear() { val_ = nullptr; }
    
    /**
     * Dereference the handle to get the underlying object.
     */
    T* operator->() const { return val_; }
    
    /**
     * Dereference the handle to get the underlying object.
     */
    T* operator*() const { return val_; }
    
    /**
     * Checks whether two handles are the same.
     */
    template <typename S>
    bool operator==(const Local<S>& that) const {
        return val_ == *that;
    }
    
    /**
     * Checks whether two handles are different.
     */
    template <typename S>
    bool operator!=(const Local<S>& that) const {
        return !operator==(that);
    }
    
    /**
     * Cast a handle to a subclass.
     */
    template <typename S>
    static Local<T> Cast(Local<S> that) {
        return Local<T>(reinterpret_cast<T*>(*that));
    }
    
    /**
     * Create a local handle for the content of another handle.
     * This is done for persistent handles to create a local handle.
     */
    static Local<T> New(Isolate* isolate, Local<T> that);
    static Local<T> New(Isolate* isolate, const Persistent<T>& that);
    
private:
    friend class Persistent<T>;
    friend class Eternal<T>;
    template <typename S> friend class Local;
    
    explicit Local(T* that) : val_(that) {}
    
    T* val_;
};

/**
 * A MaybeLocal<> is a wrapper around Local<> that enforces a check whether
 * the Local<> is empty before it can be used.
 *
 * If an API method returns a MaybeLocal<>, the API method can potentially fail
 * either because an exception is thrown, or because an exception is pending,
 * e.g. because a previous API call threw an exception that hasn't been caught
 * yet. In that case, an empty MaybeLocal is returned.
 */
template <typename T>
class MaybeLocal {
public:
    MaybeLocal() : val_() {}
    
    template <typename S>
    MaybeLocal(Local<S> that) : val_(that) {}
    
    bool IsEmpty() const { return val_.IsEmpty(); }
    
    /**
     * Converts this MaybeLocal<> to a Local<>. If this MaybeLocal<> is empty,
     * |false| is returned and |out| is left untouched.
     */
    template <typename S>
    bool ToLocal(Local<S>* out) const {
        if (val_.IsEmpty()) return false;
        *out = val_;
        return true;
    }
    
    /**
     * Converts this MaybeLocal<> to a Local<>. If this MaybeLocal<> is empty,
     * crashes the process.
     */
    Local<T> ToLocalChecked() const {
        if (val_.IsEmpty()) {
            // In real V8, this would crash. For now, we'll just return empty.
            // You might want to add proper error handling here.
        }
        return val_;
    }
    
    /**
     * Converts this MaybeLocal<> to a Local<>, using a default value if this
     * MaybeLocal<> is empty.
     */
    template <typename S>
    Local<S> FromMaybe(Local<S> default_value) const {
        return val_.IsEmpty() ? default_value : val_;
    }
    
private:
    Local<T> val_;
};

}  // namespace v8

#endif  // V8_V8_LOCAL_HANDLE_H_
