#include <iostream>
#include <cstdint>

// Extern C functions for TechnoScript runtime
extern "C" {
    void print_int64(int64_t value) {
        std::cerr << "DEBUG: print_int64 ENTRY - called with value=" << value << std::endl;
        std::cerr << "DEBUG: About to print to stdout..." << std::endl;
        std::cout << value << std::endl;
        std::cout.flush();
        std::cerr << "DEBUG: print_int64 SUCCESS - finished printing" << std::endl;
    }
    
    void print_string(const char* str) {
        std::cout << str << std::endl;
    }
}
