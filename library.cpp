#include <iostream>
#include <cstdint>
#include "goroutine.h"

// Forward declaration of runtime functions
extern "C" uint64_t runtime_sleep(int64_t milliseconds);

// Extern C functions for TechnoScript runtime
extern "C" {
    void print_int64(int64_t value) {
        std::cout << value << std::endl;
    }
    
    void print_string(const char* str) {
    std::cout << str << std::endl;
}

// Async functions implementation
uint64_t technoscript_sleep(int64_t milliseconds) {
    // Delegate to the runtime function
    return runtime_sleep(milliseconds);
}
}
