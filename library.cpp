#include <iostream>
#include <cstdint>

// Extern C functions for TechnoScript runtime
extern "C" {
    void print_int64(int64_t value) {
        std::cout << value << std::endl;
    }
}
