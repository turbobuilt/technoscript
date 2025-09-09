#include <iostream>
#include <cstdint>

// Extern C functions for TechnoScript runtime
extern "C" {
    void print_int64(int64_t value) {
        std::cerr << "DEBUG: print_int64 called with value=" << value << std::endl;
        std::cerr << "DEBUG: RDI should contain the value, checking memory..." << std::endl;
        std::cout << value << std::endl;
        std::cout.flush();
    }
    
    void print_string(const char* str) {
        std::cout << str << std::endl;
    }
}
