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
    
    // Load parameter by index into RAX (System V ABI)
    size_t emitLoadParamToRAX(int param_index) {
        switch (param_index) {
            case 0: return emitBytes({0x48, 0x89, 0xF8}); // mov rax, rdi
            case 1: return emitBytes({0x48, 0x89, 0xF0}); // mov rax, rsi  
            case 2: return emitBytes({0x48, 0x89, 0xD0}); // mov rax, rdx
            case 3: return emitBytes({0x48, 0x89, 0xC8}); // mov rax, rcx
            case 4: return emitBytes({0x4C, 0x89, 0xC0}); // mov rax, r8
            case 5: return emitBytes({0x4C, 0x89, 0xC8}); // mov rax, r9
            default:
                // Parameter is on stack - TODO: implement stack parameter access
                return 0;
        }
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

    // Append raw data (e.g. string literal)
    size_t emitData(const std::string& s) { buffer.insert(buffer.end(), s.begin(), s.end()); return s.size(); }
};