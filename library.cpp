#include <iostream>
#include <cstdint>
#include <unistd.h>

// Extern C functions for TechnoScript runtime
extern "C" {
    void print_int64(int64_t value) {
        std::cout << value << std::endl;
    }
    
    void print_string(const char* str) {
        std::cout << str << std::endl;
    }
}
