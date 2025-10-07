#ifndef V8_V8_PERSISTENT_HANDLE_H_
#define V8_V8_PERSISTENT_HANDLE_H_

#include "v8-local-handle.h"

namespace v8 {

// Forward declarations
class Isolate;

/**
 * An object reference that is independent of any handle scope.  Where
 * a Local handle only lives as long as the HandleScope in which it was
 * allocated, a Persistent handle remains valid until it is explicitly
 * disposed using Reset().
 *
 * A persistent handle contains a reference to a storage cell within
 * the V8 engine which holds an object value and which is updated by
 * the garbage collector whenever the object is moved.
 */
template <typename T>
class Persistent {
public:
    /**
     * A Persistent with no storage cell.
     */
    Persistent() : val_(nullptr) {}
    
    /**
     * Construct a Persistent from a Local.
     * When the Local is non-empty, a new storage cell is created
     * pointing to the same object.
     */
    template <typename S>
    Persistent(Isolate* isolate, Local<S> that) {
        // In real implementation, this would register with GC
        val_ = *that;
    }
    
    /**
     * If non-empty, destroy the underlying storage cell.
     */
    ~Persistent() {
        Reset();
    }
    
    /**
     * If non-empty, destroy the underlying storage cell and create a new one
     * with the contents of other if other is non empty.
     */
    template <typename S>
    void Reset(Isolate* isolate, const Local<S>& other) {
        Reset();
        if (!other.IsEmpty()) {
            val_ = *other;
        }
    }
    
    /**
     * If non-empty, destroy the underlying storage cell
     */
    void Reset() {
        val_ = nullptr;
    }
    
    /**
     * Returns true if the handle is empty.
     */
    bool IsEmpty() const { return val_ == nullptr; }
    
    /**
     * Sets the handle to be empty.
     */
    void Clear() { Reset(); }
    
    /**
     * Returns the underlying Local handle (creating one if needed).
     */
    Local<T> Get(Isolate* isolate) const {
        return Local<T>(val_);
    }
    
    template <typename S>
    bool operator==(const Persistent<S>& that) const {
        return val_ == that.val_;
    }
    
    template <typename S>
    bool operator!=(const Persistent<S>& that) const {
        return !operator==(that);
    }
    
private:
    T* val_;
    
    // Persistent handles cannot be copied
    Persistent(const Persistent&) = delete;
    Persistent& operator=(const Persistent&) = delete;
};

/**
 * A PersistentBase which has move semantics.
 *
 * UniquePersistent is a wrapper around a raw pointer that can be moved
 * but not copied.
 */
template <typename T>
class UniquePersistent {
public:
    UniquePersistent() : val_(nullptr) {}
    
    template <typename S>
    UniquePersistent(Isolate* isolate, Local<S> that) {
        val_ = *that;
    }
    
    ~UniquePersistent() {
        Reset();
    }
    
    /**
     * Move constructor.
     */
    UniquePersistent(UniquePersistent&& other) : val_(other.val_) {
        other.val_ = nullptr;
    }
    
    /**
     * Move assignment operator.
     */
    UniquePersistent& operator=(UniquePersistent&& other) {
        if (this != &other) {
            Reset();
            val_ = other.val_;
            other.val_ = nullptr;
        }
        return *this;
    }
    
    template <typename S>
    void Reset(Isolate* isolate, const Local<S>& other) {
        Reset();
        if (!other.IsEmpty()) {
            val_ = *other;
        }
    }
    
    void Reset() {
        val_ = nullptr;
    }
    
    bool IsEmpty() const { return val_ == nullptr; }
    
    Local<T> Get(Isolate* isolate) const {
        return Local<T>(val_);
    }
    
private:
    T* val_;
    
    // Disable copy constructor and assignment operator
    UniquePersistent(const UniquePersistent&) = delete;
    UniquePersistent& operator=(const UniquePersistent&) = delete;
};

/**
 * An eternal handle is a persistent handle that is never destroyed.
 * This is useful for handles to objects that are expected to live for
 * the lifetime of the isolate.
 */
template <typename T>
class Eternal {
public:
    Eternal() : val_(nullptr) {}
    
    template <typename S>
    void Set(Isolate* isolate, Local<S> handle) {
        val_ = *handle;
    }
    
    Local<T> Get(Isolate* isolate) const {
        return Local<T>(val_);
    }
    
    bool IsEmpty() const { return val_ == nullptr; }
    
private:
    T* val_;
};

}  // namespace v8

#endif  // V8_V8_PERSISTENT_HANDLE_H_
