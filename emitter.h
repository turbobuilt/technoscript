#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>

// Simple raw x86_64 machine code emitter (Linux SysV ABI)
// Provides tiny helpers for emitting individual instructions needed
// for a minimal "Hello, world" program using write + exit syscalls.
class Emitter {
public:
    std::vector<uint8_t> buffer;

    // --- low level helpers ---
    void clear() { buffer.clear(); }
    size_t emitByte(uint8_t b) { buffer.push_back(b); return 1; }
    size_t emitBytes(const std::initializer_list<uint8_t>& bytes) { buffer.insert(buffer.end(), bytes.begin(), bytes.end()); return bytes.size(); }
    size_t emitU32(uint32_t v) { for (int i = 0; i < 4; ++i) emitByte(static_cast<uint8_t>((v >> (i * 8)) & 0xFF)); return 4; }
    size_t emitU64(uint64_t v) { for (int i = 0; i < 8; ++i) emitByte(static_cast<uint8_t>((v >> (i * 8)) & 0xFF)); return 8; }

    // --- instruction helpers (encodings are fixed for the specific registers used) ---
    size_t emitCallRel32(int32_t rel) { return emitByte(0xE8) + emitU32(static_cast<uint32_t>(rel)); } // 5
    size_t emitPopRSI() { return emitByte(0x5E); } // 1
    size_t emitMovRDXImm64(uint64_t imm) { return emitBytes({0x48, 0xBA}) + emitU64(imm); } // 10
    size_t emitMovRAXImm64(uint64_t imm) { return emitBytes({0x48, 0xB8}) + emitU64(imm); } // 10
    size_t emitMovRDIImm64(uint64_t imm) { return emitBytes({0x48, 0xBF}) + emitU64(imm); } // 10
    size_t emitXorRdiRdi() { return emitBytes({0x48, 0x31, 0xFF}); } // 3
    size_t emitSyscall() { return emitBytes({0x0F, 0x05}); } // 2
    // --- additional helpers for convenience ---
    size_t emitMovRAXRDI() { return emitBytes({0x48, 0x89, 0xF8}); } // mov rax, rdi
    size_t emitAddALImm8(uint8_t imm) { return emitBytes({0x04, imm}); } // add al, imm8
    size_t emitPushRAX() { return emitByte(0x50); }
    size_t emitPopRAX() { return emitByte(0x58); } // pop rax
    size_t emitAddRSPImm8(uint8_t imm) { return emitBytes({0x48, 0x83, 0xC4, imm}); } // add rsp, imm8
    size_t emitMovRSIRSP() { return emitBytes({0x48, 0x89, 0xE6}); } // mov rsi, rsp
    size_t emitRet() { return emitByte(0xC3); }
    size_t emitPushRDI() { return emitByte(0x57); }
    size_t emitPopRDI() { return emitByte(0x5F); }
    size_t emitMovRAXRSI() { return emitBytes({0x48, 0x89, 0xF0}); } // mov rax, rsi
    
    // R15 register operations for lexical scope management
    size_t emitPushR15() { return emitBytes({0x41, 0x57}); } // push r15
    size_t emitPopR15() { return emitBytes({0x41, 0x5F}); }  // pop r15
    size_t emitMovR15RAX() { return emitBytes({0x49, 0x89, 0xC7}); } // mov r15, rax
    
    // Memory operations with R15 + offset
    size_t emitMovQwordPtrR15PlusOffsetRAX(int32_t offset) { 
        if (offset == 0) {
            return emitBytes({0x49, 0x89, 0x07}); // mov [r15], rax
        } else if (offset >= -128 && offset <= 127) {
            return emitBytes({0x49, 0x89, 0x47, static_cast<uint8_t>(offset)}); // mov [r15+offset8], rax
        } else {
            return emitBytes({0x49, 0x89, 0x87}) + emitU32(static_cast<uint32_t>(offset)); // mov [r15+offset32], rax
        }
    }
    
    size_t emitMovDwordPtrR15PlusOffsetEAX(int32_t offset) {
        if (offset == 0) {
            return emitBytes({0x41, 0x89, 0x07}); // mov [r15], eax
        } else if (offset >= -128 && offset <= 127) {
            return emitBytes({0x41, 0x89, 0x47, static_cast<uint8_t>(offset)}); // mov [r15+offset8], eax
        } else {
            return emitBytes({0x41, 0x89, 0x87}) + emitU32(static_cast<uint32_t>(offset)); // mov [r15+offset32], eax
        }
    }
    
    // Memory allocation via mmap syscall (sys_mmap = 9)
    size_t emitMovRSIImm64(uint64_t imm) { return emitBytes({0x48, 0xBE}) + emitU64(imm); } // mov rsi, imm64
    size_t emitMovRCXImm64(uint64_t imm) { return emitBytes({0x48, 0xB9}) + emitU64(imm); } // mov rcx, imm64
    size_t emitMovR8Imm64(uint64_t imm) { return emitBytes({0x49, 0xB8}) + emitU64(imm); }  // mov r8, imm64
    size_t emitMovR9Imm64(uint64_t imm) { return emitBytes({0x49, 0xB9}) + emitU64(imm); }  // mov r9, imm64
    size_t emitXorRDXRDX() { return emitBytes({0x48, 0x31, 0xD2}); } // xor rdx, rdx
    
    // Move RAX to System V ABI parameter registers
    size_t emitMovRDIRAX() { return emitBytes({0x48, 0x89, 0xC7}); } // mov rdi, rax
    size_t emitMovRSIRAX() { return emitBytes({0x48, 0x89, 0xC6}); } // mov rsi, rax
    size_t emitMovRDXRAX() { return emitBytes({0x48, 0x89, 0xC2}); } // mov rdx, rax
    size_t emitMovRCXRAX() { return emitBytes({0x48, 0x89, 0xC1}); } // mov rcx, rax
    size_t emitMovR8RAX() { return emitBytes({0x49, 0x89, 0xC0}); }  // mov r8, rax
    size_t emitMovR9RAX() { return emitBytes({0x49, 0x89, 0xC1}); }  // mov r9, rax
    
    // External function calls
    size_t emitCallAbsolute(uint64_t address) { 
        // mov rax, address; call rax
        return emitMovRAXImm64(address) + emitBytes({0xFF, 0xD0}); // call rax (12 bytes total)
    }
    
    // Emit placeholder for function address that will be patched later
    // Returns the exact offset where the 8-byte address should be written
    size_t emitFunctionAddressPlaceholder(size_t& patch_offset) {
        patch_offset = buffer.size(); // Store exact offset for patching
        return emitU64(0); // 8 bytes of zeros as placeholder
    }
    
    // System V ABI parameter register operations
    // Parameter registers: RDI, RSI, RDX, RCX, R8, R9 (0-5)
    size_t emitMovRAXFromParam(int param_index) {
        switch (param_index) {
            case 0: return emitBytes({0x48, 0x89, 0xF8}); // mov rax, rdi
            case 1: return emitBytes({0x48, 0x89, 0xF0}); // mov rax, rsi  
            case 2: return emitBytes({0x48, 0x89, 0xD0}); // mov rax, rdx
            case 3: return emitBytes({0x48, 0x89, 0xC8}); // mov rax, rcx
            case 4: return emitBytes({0x4C, 0x89, 0xC0}); // mov rax, r8
            case 5: return emitBytes({0x4C, 0x89, 0xC8}); // mov rax, r9
            default:
                // Parameter on stack: mov rax, [rsp + 8 + (param_index - 6) * 8]
                int stack_offset = 8 + (param_index - 6) * 8;
                if (stack_offset <= 127) {
                    return emitBytes({0x48, 0x8B, 0x44, 0x24, static_cast<uint8_t>(stack_offset)}); // mov rax, [rsp+offset8]
                } else {
                    return emitBytes({0x48, 0x8B, 0x84, 0x24}) + emitU32(static_cast<uint32_t>(stack_offset)); // mov rax, [rsp+offset32]
                }
        }
    }
    
    // Move RAX to System V ABI parameter register by index
    // Parameter registers: RDI, RSI, RDX, RCX, R8, R9 (0-5)
    size_t emitMovParamFromRAX(int param_index) {
        switch (param_index) {
            case 0: return emitMovRDIRAX(); // mov rdi, rax
            case 1: return emitMovRSIRAX(); // mov rsi, rax
            case 2: return emitMovRDXRAX(); // mov rdx, rax
            case 3: return emitMovRCXRAX(); // mov rcx, rax
            case 4: return emitMovR8RAX();  // mov r8, rax
            case 5: return emitMovR9RAX();  // mov r9, rax
            default:
                // Push RAX to stack for parameters beyond 6
                // For now, we'll return 0 - stack parameters will be implemented later
                return 0;
        }
    }
    
    // --- Flexible register helpers ---
    
    // Get register encoding for ModR/M byte (REX prefix handled separately)
    uint8_t getRegisterEncoding(int reg_num) {
        return reg_num & 0x7; // Lower 3 bits
    }
    
    // Check if register needs REX prefix (R8-R15)
    bool needsRexPrefix(int reg_num) {
        return reg_num >= 8;
    }
    
    // Generate MOV instruction from memory [base_reg + offset] to target_reg
    size_t emitMovRegFromMemory(int target_reg, int base_reg, int32_t offset) {
        size_t total_length = 0;
        
        // Determine REX prefix
        uint8_t rex = 0x48; // 64-bit operand size
        if (target_reg >= 8) rex |= 0x04; // REX.R
        if (base_reg >= 8) rex |= 0x01;   // REX.B
        
        total_length += emitBytes({rex});
        
        // Opcode: MOV r64, r/m64
        total_length += emitBytes({0x8B});
        
        // ModR/M byte: mod=00/01/10, reg=target_reg, r/m=base_reg
        uint8_t target_encoded = getRegisterEncoding(target_reg);
        uint8_t base_encoded = getRegisterEncoding(base_reg);
        
        if (offset == 0 && base_encoded != 5) { // RBP requires displacement
            // mod=00: [reg]
            uint8_t modrm = (target_encoded << 3) | base_encoded;
            total_length += emitBytes({modrm});
        } else if (offset >= -128 && offset <= 127) {
            // mod=01: [reg + disp8]
            uint8_t modrm = 0x40 | (target_encoded << 3) | base_encoded;
            total_length += emitBytes({modrm, static_cast<uint8_t>(offset)});
        } else {
            // mod=10: [reg + disp32]
            uint8_t modrm = 0x80 | (target_encoded << 3) | base_encoded;
            total_length += emitBytes({modrm});
            total_length += emitU32(static_cast<uint32_t>(offset));
        }
        
        return total_length;
    }
    
    // Generate MOV instruction from parameter register to target register
    size_t emitMovRegFromParam(int target_reg, int param_index) {
        // Parameter registers: RDI(7), RSI(6), RDX(2), RCX(1), R8(8), R9(9)
        int param_regs[] = {7, 6, 2, 1, 8, 9}; // RDI, RSI, RDX, RCX, R8, R9
        
        if (param_index < 6) {
            int src_reg = param_regs[param_index];
            return emitMovRegFromReg(target_reg, src_reg);
        } else {
            // Parameter on stack
            int stack_offset = 8 + (param_index - 6) * 8;
            return emitMovRegFromMemory(target_reg, 4, stack_offset); // RSP = 4
        }
    }
    
    // Generate MOV instruction from source register to target register
    size_t emitMovRegFromReg(int target_reg, int src_reg) {
        size_t total_length = 0;
        
        // Determine REX prefix
        uint8_t rex = 0x48; // 64-bit operand size
        if (target_reg >= 8) rex |= 0x04; // REX.R
        if (src_reg >= 8) rex |= 0x01;    // REX.B
        
        total_length += emitBytes({rex});
        
        // Opcode: MOV r64, r64
        total_length += emitBytes({0x89});
        
        // ModR/M byte: mod=11, reg=src_reg, r/m=target_reg
        uint8_t src_encoded = getRegisterEncoding(src_reg);
        uint8_t target_encoded = getRegisterEncoding(target_reg);
        uint8_t modrm = 0xC0 | (src_encoded << 3) | target_encoded;
        
        total_length += emitBytes({modrm});
        
        return total_length;
    }

    // Append raw data (e.g. string literal)
    size_t emitData(const std::string& s) { buffer.insert(buffer.end(), s.begin(), s.end()); return s.size(); }
};