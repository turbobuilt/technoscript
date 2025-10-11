#pragma once
#include <cstdint>

// Safe Unordered List structure layout
struct SafeUnorderedListHeader {
    uint64_t lock;              // Bit 0: locked flag, bits 1-63: reserved
    uint64_t length;            // Total allocated capacity  
    uint64_t next_available;    // Next available slot index
    uint64_t used_slots;        // Number of used slots
    // Data follows immediately after header (qword * length)
};

// Extern C functions for TechnoScript runtime
extern "C" {
    void print_int64(int64_t value);
    void print_string(const char* str);
    
    // Async functions
    uint64_t sleep(int64_t milliseconds);  // Returns promise ID
}
