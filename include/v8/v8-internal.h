#ifndef V8_V8_INTERNAL_H_
#define V8_V8_INTERNAL_H_

#include <cstddef>
#include <cstdint>

namespace v8 {
namespace internal {

// Forward declarations for internal types
class Isolate;
class Object;
class Context;

// Internal address type
typedef uintptr_t Address;

// Tagged pointer representation
// In TechnoScript, we'll use actual pointers for simplicity
// Real V8 uses pointer tagging for SMI optimization
class Tagged {
public:
    Tagged() : ptr_(0) {}
    explicit Tagged(Address addr) : ptr_(addr) {}
    
    Address value() const { return ptr_; }
    bool IsHeapObject() const { return ptr_ != 0; }
    
private:
    Address ptr_;
};

}  // namespace internal
}  // namespace v8

#endif  // V8_V8_INTERNAL_H_
