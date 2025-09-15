#include "debugger.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>

UnicornDebugger::UnicornDebugger() : uc(nullptr), capstone_handle(0), code_base(0), code_size(0),
                                    heap_base(0), heap_size(0), stack_base(0), stack_size(0), next_alloc_address(0) {
}

UnicornDebugger::~UnicornDebugger() {
    if (uc) {
        uc_close(uc);
    }
    if (capstone_handle) {
        cs_close(&capstone_handle);
    }
}

bool UnicornDebugger::initialize() {
    // Initialize Unicorn for x86_64
    uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err != UC_ERR_OK) {
        last_error = "Failed to initialize Unicorn: " + std::string(uc_strerror(err));
        return false;
    }
    
    // Initialize Capstone for disassembly
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstone_handle) != CS_ERR_OK) {
        last_error = "Failed to initialize Capstone";
        return false;
    }
    
    // Set up hooks for debugging
    uc_hook hook;
    
    // Hook all code execution
    uc_hook_add(uc, &hook, UC_HOOK_CODE, (void*)hookCode, this, 1, 0);
    
    // Hook invalid memory access
    uc_hook_add(uc, &hook, UC_HOOK_MEM_INVALID, (void*)hookMemoryInvalid, this, 1, 0);
    
    // Hook unmapped memory access  
    uc_hook_add(uc, &hook, UC_HOOK_MEM_UNMAPPED, (void*)hookMemoryUnmapped, this, 1, 0);
    
    // Hook interrupts (syscalls)
    uc_hook_add(uc, &hook, UC_HOOK_INTR, (void*)hookInterrupt, this, 1, 0);
    
    std::cout << "UNICORN: Debugger initialized successfully" << std::endl;
    return true;
}

bool UnicornDebugger::setupMemory(uint64_t heap_start, uint64_t heap_size_param, uint64_t stack_start, uint64_t stack_size_param) {
    this->heap_base = heap_start;
    this->heap_size = heap_size_param;
    this->stack_base = stack_start;
    this->stack_size = stack_size_param;
    
    // Set up allocation tracking - start allocations after heap
    this->next_alloc_address = heap_start + heap_size_param;
    
    // Ensure sizes are page-aligned (4KB)
    size_t aligned_heap_size = (heap_size_param + 4095) & ~4095;
    size_t aligned_stack_size = (stack_size_param + 4095) & ~4095;
    
    // Map heap memory (read/write)
    uc_err err = uc_mem_map(uc, heap_start, aligned_heap_size, UC_PROT_READ | UC_PROT_WRITE);
    if (err != UC_ERR_OK) {
        last_error = "Failed to map heap memory: " + std::string(uc_strerror(err));
        return false;
    }
    
    // Map stack memory (read/write)
    err = uc_mem_map(uc, stack_start, aligned_stack_size, UC_PROT_READ | UC_PROT_WRITE);
    if (err != UC_ERR_OK) {
        last_error = "Failed to map stack memory: " + std::string(uc_strerror(err));
        return false;
    }
    
    // Pre-allocate memory region for dynamic allocations (for syscalls)
    uint64_t alloc_region_base = heap_start + aligned_heap_size;
    uint64_t alloc_region_size = 0x100000; // 1MB for allocations
    err = uc_mem_map(uc, alloc_region_base, alloc_region_size, UC_PROT_READ | UC_PROT_WRITE);
    if (err != UC_ERR_OK) {
        last_error = "Failed to map allocation region: " + std::string(uc_strerror(err));
        return false;
    }
    
    // Initialize stack pointer to top of stack
    setRegister(UC_X86_REG_RSP, stack_start + stack_size_param - 8);
    setRegister(UC_X86_REG_RBP, stack_start + stack_size_param - 8);
    
    std::cout << "UNICORN: Memory setup complete" << std::endl;
    std::cout << "  Heap: 0x" << std::hex << heap_start << " - 0x" << (heap_start + aligned_heap_size) << std::endl;
    std::cout << "  Stack: 0x" << stack_start << " - 0x" << (stack_start + aligned_stack_size) << std::endl;
    std::cout << "  Alloc region: 0x" << alloc_region_base << " - 0x" << (alloc_region_base + alloc_region_size) << std::dec << std::endl;
    
    return true;
}

bool UnicornDebugger::loadCode(const uint8_t* code, size_t size, uint64_t base_address) {
    this->code_base = base_address;
    this->code_size = size;
    
    // Round up size to page boundary (4KB)
    size_t aligned_size = (size + 4095) & ~4095;
    
    // Map code memory (read/execute)
    uc_err err = uc_mem_map(uc, base_address, aligned_size, UC_PROT_READ | UC_PROT_EXEC);
    if (err != UC_ERR_OK) {
        last_error = "Failed to map code memory: " + std::string(uc_strerror(err));
        return false;
    }
    
    // Write code to memory
    err = uc_mem_write(uc, base_address, code, size);
    if (err != UC_ERR_OK) {
        last_error = "Failed to write code to memory: " + std::string(uc_strerror(err));
        return false;
    }
    
    std::cout << "UNICORN: Code loaded at 0x" << std::hex << base_address << " (size: " << std::dec << size << " bytes, aligned: " << aligned_size << " bytes)" << std::endl;
    return true;
}

void UnicornDebugger::registerExternalFunction(uint64_t address, const std::string& name) {
    external_functions[address] = name;
    std::cout << "UNICORN: Registered external function '" << name << "' at 0x" << std::hex << address << std::dec << std::endl;
}

bool UnicornDebugger::step() {
    uint64_t pc = getRegister(UC_X86_REG_RIP);
    
    // Check for breakpoints
    for (uint64_t bp : breakpoints) {
        if (pc == bp) {
            std::cout << "UNICORN: Hit breakpoint at 0x" << std::hex << pc << std::dec << std::endl;
            dumpRegisters();
            return true;
        }
    }
    
    // Execute one instruction
    uc_err err = uc_emu_start(uc, pc, pc + 20, 0, 1); // Execute 1 instruction
    if (err != UC_ERR_OK) {
        last_error = "Execution failed: " + std::string(uc_strerror(err));
        std::cout << "UNICORN: " << last_error << " at 0x" << std::hex << pc << std::dec << std::endl;
        dumpRegisters();
        return false;
    }
    
    return true;
}

bool UnicornDebugger::run(uint64_t start_address, uint64_t end_address) {
    if (end_address == 0) {
        end_address = code_base + code_size;
    }
    
    std::cout << "UNICORN: Starting execution from 0x" << std::hex << start_address;
    if (end_address != code_base + code_size) {
        std::cout << " to 0x" << end_address;
    }
    std::cout << std::dec << std::endl;
    
    uc_err err = uc_emu_start(uc, start_address, end_address, 0, 0);
    if (err != UC_ERR_OK) {
        last_error = "Execution failed: " + std::string(uc_strerror(err));
        std::cout << "UNICORN: " << last_error << std::endl;
        uint64_t pc = getRegister(UC_X86_REG_RIP);
        std::cout << "UNICORN: Failed at PC: 0x" << std::hex << pc << std::dec << std::endl;
        dumpRegisters();
        disassembleAt(pc, 5);
        return false;
    }
    
    std::cout << "UNICORN: Execution completed successfully" << std::endl;
    return true;
}

void UnicornDebugger::setBreakpoint(uint64_t address) {
    breakpoints.push_back(address);
    std::cout << "UNICORN: Breakpoint set at 0x" << std::hex << address << std::dec << std::endl;
}

void UnicornDebugger::removeBreakpoint(uint64_t address) {
    auto it = std::find(breakpoints.begin(), breakpoints.end(), address);
    if (it != breakpoints.end()) {
        breakpoints.erase(it);
        std::cout << "UNICORN: Breakpoint removed from 0x" << std::hex << address << std::dec << std::endl;
    }
}

void UnicornDebugger::dumpRegisters() {
    std::cout << "UNICORN: Register dump:" << std::endl;
    std::cout << "  RAX: 0x" << std::hex << std::setw(16) << std::setfill('0') << getRegister(UC_X86_REG_RAX) << std::endl;
    std::cout << "  RBX: 0x" << std::setw(16) << std::setfill('0') << getRegister(UC_X86_REG_RBX) << std::endl;
    std::cout << "  RCX: 0x" << std::setw(16) << std::setfill('0') << getRegister(UC_X86_REG_RCX) << std::endl;
    std::cout << "  RDX: 0x" << std::setw(16) << std::setfill('0') << getRegister(UC_X86_REG_RDX) << std::endl;
    std::cout << "  RSI: 0x" << std::setw(16) << std::setfill('0') << getRegister(UC_X86_REG_RSI) << std::endl;
    std::cout << "  RDI: 0x" << std::setw(16) << std::setfill('0') << getRegister(UC_X86_REG_RDI) << std::endl;
    std::cout << "  RSP: 0x" << std::setw(16) << std::setfill('0') << getRegister(UC_X86_REG_RSP) << std::endl;
    std::cout << "  RBP: 0x" << std::setw(16) << std::setfill('0') << getRegister(UC_X86_REG_RBP) << std::endl;
    std::cout << "  R8:  0x" << std::setw(16) << std::setfill('0') << getRegister(UC_X86_REG_R8) << std::endl;
    std::cout << "  R9:  0x" << std::setw(16) << std::setfill('0') << getRegister(UC_X86_REG_R9) << std::endl;
    std::cout << "  R10: 0x" << std::setw(16) << std::setfill('0') << getRegister(UC_X86_REG_R10) << std::endl;
    std::cout << "  R15: 0x" << std::setw(16) << std::setfill('0') << getRegister(UC_X86_REG_R15) << std::endl;
    std::cout << "  RIP: 0x" << std::setw(16) << std::setfill('0') << getRegister(UC_X86_REG_RIP) << std::dec << std::endl;
}

void UnicornDebugger::dumpMemory(uint64_t address, size_t size) {
    std::vector<uint8_t> buffer(size);
    if (readMemory(address, buffer.data(), size)) {
        std::cout << "UNICORN: Memory dump at 0x" << std::hex << address << ":" << std::endl;
        for (size_t i = 0; i < size; i += 16) {
            std::cout << "  0x" << std::setw(8) << std::setfill('0') << (address + i) << ": ";
            for (size_t j = 0; j < 16 && i + j < size; ++j) {
                std::cout << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i + j]) << " ";
            }
            std::cout << std::endl;
        }
        std::cout << std::dec;
    }
}

void UnicornDebugger::disassembleAt(uint64_t address, size_t count) {
    std::vector<uint8_t> code(count * 16); // Max instruction size
    if (readMemory(address, code.data(), code.size())) {
        cs_insn* insn;
        size_t instruction_count = cs_disasm(capstone_handle, code.data(), code.size(), address, count, &insn);
        
        if (instruction_count > 0) {
            std::cout << "UNICORN: Disassembly at 0x" << std::hex << address << ":" << std::endl;
            for (size_t i = 0; i < instruction_count; ++i) {
                std::cout << "  0x" << std::setw(8) << std::setfill('0') << insn[i].address << ": ";
                std::cout << insn[i].mnemonic << " " << insn[i].op_str << std::endl;
            }
            cs_free(insn, instruction_count);
        }
        std::cout << std::dec;
    }
}

uint64_t UnicornDebugger::getRegister(uc_x86_reg reg) {
    uint64_t value;
    uc_reg_read(uc, reg, &value);
    return value;
}

void UnicornDebugger::setRegister(uc_x86_reg reg, uint64_t value) {
    uc_reg_write(uc, reg, &value);
}

bool UnicornDebugger::readMemory(uint64_t address, void* buffer, size_t size) {
    uc_err err = uc_mem_read(uc, address, buffer, size);
    if (err != UC_ERR_OK) {
        last_error = "Failed to read memory: " + std::string(uc_strerror(err));
        return false;
    }
    return true;
}

bool UnicornDebugger::writeMemory(uint64_t address, const void* buffer, size_t size) {
    uc_err err = uc_mem_write(uc, address, buffer, size);
    if (err != UC_ERR_OK) {
        last_error = "Failed to write memory: " + std::string(uc_strerror(err));
        return false;
    }
    return true;
}

void UnicornDebugger::hookCode(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    UnicornDebugger* debugger = static_cast<UnicornDebugger*>(user_data);
    
    // Check for call to external function
    uint8_t code[16];
    uc_mem_read(uc, address, code, std::min(size, (uint32_t)16));
    
    // Look for call instruction (0xff 0xd0 or 0xe8 or direct call patterns)
    // For x86_64, check for patterns like "movabs rax, address; call rax" or direct call
    if (size >= 2) {
        // Check for "call rax" (0xff 0xd0)
        if (code[0] == 0xff && code[1] == 0xd0) {
            uint64_t rax;
            uc_reg_read(uc, UC_X86_REG_RAX, &rax);
            
            auto it = debugger->external_functions.find(rax);
            if (it != debugger->external_functions.end()) {
                uint64_t rdi;
                uc_reg_read(uc, UC_X86_REG_RDI, &rdi);
                
                std::cout << "UNICORN: Calling external function " << it->second << " with arg: " << rdi << std::endl;
                
                if (it->second == "print_int64") {
                    std::cout << rdi << std::endl;
                }
                
                // Skip the call instruction by advancing RIP by 2 bytes
                uint64_t rip = address + 2;
                uc_reg_write(uc, UC_X86_REG_RIP, &rip);
                return;
            }
        }
    }
    
    // Check for syscall instruction
    // Look for syscall instruction (0x0f 0x05)
    if (size >= 2 && code[0] == 0x0f && code[1] == 0x05) {
        std::cout << "UNICORN: Syscall detected at 0x" << std::hex << address << std::dec << std::endl;
        
        uint64_t rax, rdi, rsi, rdx;
        uc_reg_read(uc, UC_X86_REG_RAX, &rax);
        uc_reg_read(uc, UC_X86_REG_RDI, &rdi);
        uc_reg_read(uc, UC_X86_REG_RSI, &rsi);
        uc_reg_read(uc, UC_X86_REG_RDX, &rdx);
        
        std::cout << "UNICORN: Syscall intercepted - rax=" << rax << ", rdi=" << rdi << ", rsi=" << rsi << ", rdx=" << rdx << std::endl;
        
        if (rax == 12) { // brk/mmap syscall
            // This appears to be mmap - allocate memory
            uint64_t size = rdi;  // Size might be in different register based on calling convention
            if (size == 0) {
                // If size is 0, this might be asking for current break
                uc_reg_write(uc, UC_X86_REG_RAX, &debugger->next_alloc_address);
            } else {
                // Allocate memory by returning a valid address
                uint64_t allocated_addr = debugger->next_alloc_address;
                size_t aligned_size = (size + 4095) & ~4095; // Align to page boundary
                
                // Map the memory region in Unicorn
                uc_err err = uc_mem_map(uc, allocated_addr, aligned_size, UC_PROT_READ | UC_PROT_WRITE);
                if (err != UC_ERR_OK) {
                    std::cout << "UNICORN: Failed to map allocated memory: " << uc_strerror(err) << std::endl;
                    uint64_t error_result = 0;
                    uc_reg_write(uc, UC_X86_REG_RAX, &error_result);
                } else {
                    debugger->next_alloc_address += aligned_size;
                    std::cout << "UNICORN: Allocated and mapped " << size << " bytes at 0x" << std::hex << allocated_addr << std::dec << std::endl;
                    uc_reg_write(uc, UC_X86_REG_RAX, &allocated_addr);
                }
            }
        } else if (rax == 60) { // exit syscall
            std::cout << "UNICORN: Program exit requested with code " << rdi << std::endl;
            // Stop execution by setting RIP to end
            uint64_t end_addr = debugger->code_base + debugger->code_size;
            uc_reg_write(uc, UC_X86_REG_RIP, &end_addr);
            return;
        } else {
            std::cout << "UNICORN: Unknown syscall " << rax << std::endl;
            // Return 0 for unknown syscalls
            uint64_t result = 0;
            uc_reg_write(uc, UC_X86_REG_RAX, &result);
        }
        
        // Skip the syscall instruction
        uint64_t next_addr = address + 2;
        uc_reg_write(uc, UC_X86_REG_RIP, &next_addr);
    }
    
    // Print current instruction for very detailed debugging
    if (false) { // Enable for super verbose output
        std::cout << "UNICORN: Executing at 0x" << std::hex << address << std::dec << " (size: " << size << ")" << std::endl;
        debugger->disassembleAt(address, 1);
    }
}

void UnicornDebugger::hookMemoryInvalid(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data) {
    UnicornDebugger* debugger = static_cast<UnicornDebugger*>(user_data);
    
    std::cout << "UNICORN: INVALID MEMORY ACCESS!" << std::endl;
    std::cout << "  Type: " << (type == UC_MEM_READ ? "READ" : type == UC_MEM_WRITE ? "WRITE" : "FETCH") << std::endl;
    std::cout << "  Address: 0x" << std::hex << address << std::endl;
    std::cout << "  Size: " << std::dec << size << std::endl;
    if (type == UC_MEM_WRITE) {
        std::cout << "  Value: 0x" << std::hex << value << std::endl;
    }
    std::cout << std::dec;
    
    uint64_t pc = debugger->getRegister(UC_X86_REG_RIP);
    std::cout << "  PC: 0x" << std::hex << pc << std::dec << std::endl;
    
    debugger->dumpRegisters();
    debugger->disassembleAt(pc, 3);
}

bool UnicornDebugger::hookMemoryUnmapped(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data) {
    UnicornDebugger* debugger = static_cast<UnicornDebugger*>(user_data);
    
    std::cout << "UNICORN: UNMAPPED MEMORY ACCESS!" << std::endl;
    std::cout << "  Type: " << (type == UC_MEM_READ ? "READ" : type == UC_MEM_WRITE ? "WRITE" : "FETCH") << std::endl;
    std::cout << "  Address: 0x" << std::hex << address << std::endl;
    std::cout << "  Size: " << std::dec << size << std::endl;
    if (type == UC_MEM_WRITE) {
        std::cout << "  Value: 0x" << std::hex << value << std::endl;
    }
    std::cout << std::dec;
    
    uint64_t pc = debugger->getRegister(UC_X86_REG_RIP);
    std::cout << "  PC: 0x" << std::hex << pc << std::dec << std::endl;
    
    debugger->dumpRegisters();
    debugger->disassembleAt(pc, 3);
    
    return false; // Don't continue execution
}

void UnicornDebugger::hookInterrupt(uc_engine* uc, uint32_t intno, void* user_data) {
    UnicornDebugger* debugger = static_cast<UnicornDebugger*>(user_data);
    
    if (intno == 0x80) { // Syscall interrupt
        uint64_t rax, rdi, rsi, rdx;
        uc_reg_read(uc, UC_X86_REG_RAX, &rax);
        uc_reg_read(uc, UC_X86_REG_RDI, &rdi);
        uc_reg_read(uc, UC_X86_REG_RSI, &rsi);
        uc_reg_read(uc, UC_X86_REG_RDX, &rdx);
        
        std::cout << "UNICORN: Syscall intercepted - rax=" << rax << ", rdi=" << rdi << ", rsi=" << rsi << ", rdx=" << rdx << std::endl;
        
        if (rax == 12) { // brk/mmap syscall
            // This appears to be mmap - allocate memory
            uint64_t size = rdi;  // Size might be in different register based on calling convention
            if (size == 0) {
                // If size is 0, this might be asking for current break
                uc_reg_write(uc, UC_X86_REG_RAX, &debugger->next_alloc_address);
            } else {
                // Allocate memory by returning a valid address
                uint64_t allocated_addr = debugger->next_alloc_address;
                size_t aligned_size = (size + 4095) & ~4095; // Align to page boundary
                
                // Map the memory region in Unicorn
                uc_err err = uc_mem_map(uc, allocated_addr, aligned_size, UC_PROT_READ | UC_PROT_WRITE);
                if (err != UC_ERR_OK) {
                    std::cout << "UNICORN: Failed to map allocated memory: " << uc_strerror(err) << std::endl;
                    uint64_t error_result = 0;
                    uc_reg_write(uc, UC_X86_REG_RAX, &error_result);
                } else {
                    debugger->next_alloc_address += aligned_size;
                    std::cout << "UNICORN: Allocated and mapped " << size << " bytes at 0x" << std::hex << allocated_addr << std::dec << std::endl;
                    uc_reg_write(uc, UC_X86_REG_RAX, &allocated_addr);
                }
            }
        } else if (rax == 60) { // exit syscall
            std::cout << "UNICORN: Program exit requested with code " << rdi << std::endl;
            // Stop execution by returning
            return;
        } else {
            std::cout << "UNICORN: Unknown syscall " << rax << std::endl;
            // Return 0 for unknown syscalls
            uint64_t result = 0;
            uc_reg_write(uc, UC_X86_REG_RAX, &result);
        }
    }
}
