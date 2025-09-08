#pragma once
#include <cstdint>

// Extern C functions for TechnoScript runtime
extern "C" {
    void print_int64(int64_t value);
    void print_string(const char* str);
}
