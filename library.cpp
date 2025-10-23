#include <iostream>
#include <iomanip>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include "goroutine.h"
#include "ast.h"

// Forward declaration of runtime functions
extern "C" uint64_t runtime_sleep(int64_t milliseconds);

// Extern C functions for TechnoScript runtime
extern "C" {
    void print_int64(int64_t value) {
        std::printf("%lld\n", static_cast<long long>(value));
    }

    void print_float64(double value) {
        std::printf("%g\n", value);
    }

    void print_any(uint64_t type, uint64_t value) {
        if (type == static_cast<uint64_t>(DataType::FLOAT64)) {
            union {
                uint64_t u;
                double d;
            } converter;
            converter.u = value;
            std::printf("%g\n", converter.d);
        } else {
            std::printf("[print_any type=%llu value=0x%llx]\n",
                        static_cast<unsigned long long>(type),
                        static_cast<unsigned long long>(value));
        }
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
