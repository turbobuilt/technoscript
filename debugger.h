#pragma once

#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <cstdint>
#include <vector>
#include <string>
#include <map>
#include <functional>

class UnicornDebugger {
public:
    UnicornDebugger();
    ~UnicornDebugger();
    
    // Initialize the emulation environment
    bool initialize();
    
    // Load binary code into the emulator
    bool loadCode(const uint8_t* code, size_t size, uint64_t base_address);
    
    // Set up memory regions
    bool setupMemory(uint64_t heap_start, uint64_t heap_size, uint64_t stack_start, uint64_t stack_size);
    
    // Register external function mappings (like print_int64)
    void registerExternalFunction(uint64_t address, const std::string& name);
    
    // Step-by-step execution
    bool step();
    bool run(uint64_t start_address, uint64_t end_address = 0);
    
    // Debugging features
    void setBreakpoint(uint64_t address);
    void removeBreakpoint(uint64_t address);
    void dumpRegisters();
    void dumpMemory(uint64_t address, size_t size);
    void disassembleAt(uint64_t address, size_t count = 1);
    
    // Register access
    uint64_t getRegister(uc_x86_reg reg);
    void setRegister(uc_x86_reg reg, uint64_t value);
    
    // Memory access
    bool readMemory(uint64_t address, void* buffer, size_t size);
    bool writeMemory(uint64_t address, const void* buffer, size_t size);
    
    // Error handling
    std::string getLastError() const { return last_error; }
    
private:
    uc_engine* uc;
    csh capstone_handle;
    std::string last_error;
    
    // Memory layout
    uint64_t code_base;
    uint64_t code_size;
    uint64_t heap_base;
    uint64_t heap_size;
    uint64_t stack_base;
    uint64_t stack_size;
    
    // Debugging state
    std::vector<uint64_t> breakpoints;
    std::map<uint64_t, std::string> external_functions;
    
    // Memory allocation tracking for syscalls
    uint64_t next_alloc_address;
    
    // Callbacks
    static void hookCode(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
    static void hookMemoryInvalid(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);
    static bool hookMemoryUnmapped(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);
    static void hookInterrupt(uc_engine* uc, uint32_t intno, void* user_data);
    
    // Helper methods
    void printInstruction(uint64_t address, const uint8_t* code, size_t size);
    void handleExternalCall(uint64_t address);
    
    // Register names for debugging
    std::string getRegisterName(uc_x86_reg reg);
};
