#include "codegen.h"
#include "library.h"
#include <iostream>
#include <cstring>
#include <iomanip>

void Codegen::initExternFunctions() {
    // Get addresses of extern C functions for maximum performance
    extern_function_addresses["print_int64"] = reinterpret_cast<uint64_t>(print_int64);
    extern_function_addresses["print_string"] = reinterpret_cast<uint64_t>(print_string);
}

size_t Codegen::allocateScope(LexicalScopeNode* scope, bool is_global) {
    size_t total_length = 0;
    
    // Save R15 (current lexical scope pointer) on stack
    total_length += emitter.emitBytes({0x41, 0x57}); // push r15
    
    // Get current brk (program break) - this will be our allocated memory
    total_length += emitter.emitMovRAXImm64(12);       // sys_brk (12)
    total_length += emitter.emitBytes({0x48, 0x31, 0xFF}); // xor rdi, rdi (0)
    total_length += emitter.emitSyscall();
    
    // Save current brk in RBX
    total_length += emitter.emitBytes({0x48, 0x89, 0xC3}); // mov rbx, rax
    
    // Set new brk to current + scope size
    total_length += emitter.emitMovRAXImm64(12);       // sys_brk
    total_length += emitter.emitBytes({0x48, 0x89, 0xD9}); // mov rcx, rbx  
    total_length += emitter.emitBytes({0x48, 0x81, 0xC1}); // add rcx, imm32
    total_length += emitter.emitU32(static_cast<uint32_t>(scope->totalSize));
    total_length += emitter.emitBytes({0x49, 0x89, 0xCA}); // mov r10, rcx (use R10 instead of RDI)
    total_length += emitter.emitBytes({0x4C, 0x89, 0xD7}); // mov rdi, r10 (move to RDI only for syscall)
    total_length += emitter.emitSyscall();
    total_length += emitter.emitBytes({0x4C, 0x89, 0xD1}); // mov rcx, r10 (restore rcx from r10 for later use)
    
    // Use the old brk value as our allocated memory
    total_length += emitter.emitBytes({0x48, 0x89, 0xD8}); // mov rax, rbx
    
    // Move allocated memory address to R15 (our lexical scope pointer)
    total_length += emitter.emitMovR15RAX();
    
    return total_length;
}

size_t Codegen::restoreScope() {
    // Restore previous R15 value from stack
    return emitter.emitPopR15();
}

size_t Codegen::setupScope(LexicalScopeNode* scope, bool is_global) {
    size_t total_length = 0;
    
    // Allocate memory for this scope
    total_length += allocateScope(scope, is_global);
    
    // Create closures (implement hoisting) - this is the same for both global and function scopes
    total_length += createClosures(scope);
    
    return total_length;
}

size_t Codegen::generateNode(ASTNode* node, LexicalScopeNode* current_scope) {
    size_t total_length = 0;
    
    switch (node->type) {
        case NodeType::VAR_DECL: {
            VarDeclNode* varDecl = static_cast<VarDeclNode*>(node);
            total_length += generateVarDecl(varDecl, current_scope);
            break;
        }
        case NodeType::LITERAL: {
            LiteralNode* literal = static_cast<LiteralNode*>(node);
            total_length += generateLiteral(literal);
            break;
        }
        case NodeType::IDENTIFIER: {
            IdentifierNode* identifier = static_cast<IdentifierNode*>(node);
            
            // Check if this identifier refers to a closure (function)
            if (identifier->varRef && identifier->varRef->type == DataType::CLOSURE) {
                // Treat this as a function call
                FunctionCallNode dummy_call(identifier->value);
                dummy_call.type = NodeType::FUNCTION_CALL;
                // Copy varRef for function resolution
                dummy_call.varRef = identifier->varRef;
                total_length += generateFunctionCall(&dummy_call, current_scope);
            } else {
                total_length += generateIdentifier(identifier, current_scope);
            }
            break;
        }
        case NodeType::PRINT_STMT: {
            total_length += generatePrintStatement(node, current_scope);
            break;
        }
        case NodeType::FUNCTION_DECL: {
            FunctionDeclNode* funcDecl = static_cast<FunctionDeclNode*>(node);
            
            // Set the function address to current position in buffer
            funcDecl->functionAddress = emitter.buffer.size();
            
            // Simplified prologue - caller already set up R15 with parameters
            total_length += emitter.emitBytes({0x55}); // push rbp
            total_length += emitter.emitBytes({0x48, 0x89, 0xE5}); // mov rbp, rsp
            
            // Generate function body (children of this node)
            // Parameters are already in R15+offset, no need to copy from registers
            for (auto& child : funcDecl->ASTNode::children) {
                total_length += generateNode(child.get(), funcDecl);
            }
            
            // Simplified epilogue - caller handles R15 restoration
            total_length += emitter.emitBytes({0x48, 0x89, 0xEC}); // mov rsp, rbp
            total_length += emitter.emitBytes({0x5D}); // pop rbp
            total_length += emitter.emitBytes({0xC3}); // ret
            
            break;
        }
        case NodeType::FUNCTION_CALL: {
            FunctionCallNode* funcCall = static_cast<FunctionCallNode*>(node);
            total_length += generateFunctionCall(funcCall, current_scope);
            break;
        }
        case NodeType::GO_STMT:
            // TODO: Implement these later
            break;
        default:
            printf("DEBUG: Unhandled node type: %d\n", (int)node->type);
            
            // Special handling for identifiers that might be function calls
            if (node->type == NodeType::IDENTIFIER) {
                IdentifierNode* identifier = static_cast<IdentifierNode*>(node);
                printf("DEBUG: Processing identifier: %s\n", identifier->value.c_str());
                printf("DEBUG: varRef = %p\n", identifier->varRef);
                
                if (identifier->varRef) {
                    printf("DEBUG: varRef type = %d\n", (int)identifier->varRef->type);
                }
                
                // Check if this identifier refers to a closure (function)
                if (identifier->varRef && identifier->varRef->type == DataType::CLOSURE) {
                    printf("DEBUG: Identifier refers to a closure, treating as function call\n");
                    
                    // Treat this as a function call
                    FunctionCallNode dummy_call(identifier->value);
                    dummy_call.type = NodeType::FUNCTION_CALL;
                    total_length += generateFunctionCall(&dummy_call, current_scope);
                    break;
                } else {
                    printf("DEBUG: Identifier does not refer to a closure\n");
                }
            }
            
            // For other node types, just process children
            for (auto& child : node->children) {
                total_length += generateNode(child.get(), current_scope);
            }
            break;
    }
    
    return total_length;
}

size_t Codegen::generateVarDecl(VarDeclNode* varDecl, LexicalScopeNode* current_scope) {
    size_t total_length = 0;
    
    // Find the variable info in the current scope
    auto it = current_scope->variables.find(varDecl->varName);
    if (it == current_scope->variables.end()) {
        std::cerr << "Variable not found in scope: " << varDecl->varName << std::endl;
        return 0;
    }
    
    VariableInfo& varInfo = it->second;
    
    // Generate code for the initializer (if any)
    if (!varDecl->children.empty()) {
        // Assuming first child is the initializer
        total_length += generateNode(varDecl->children[0].get(), current_scope);
        
        // Store the value (currently in RAX) to R15 + offset
        if (varInfo.type == DataType::INT32) {
            total_length += emitter.emitMovDwordPtrR15PlusOffsetEAX(varInfo.offset);
        } else if (varInfo.type == DataType::INT64) {
            total_length += emitter.emitMovQwordPtrR15PlusOffsetRAX(varInfo.offset);
        }
    }
    
    return total_length;
}

size_t Codegen::generateLiteral(LiteralNode* literal) {
    // Convert literal value to integer and load into RAX
    int64_t value = std::stoll(literal->value);
    return emitter.emitMovRAXImm64(static_cast<uint64_t>(value));
}

size_t Codegen::generateIdentifier(IdentifierNode* identifier, LexicalScopeNode* current_scope) {
    // Use the flexible helper to load variable into RAX (maintaining backward compatibility)
    return loadVariableIntoRegister(identifier, current_scope, Register::RAX);
}

size_t Codegen::generateFunctionCall(FunctionCallNode* funcCall, LexicalScopeNode* current_scope) {
    size_t total_length = 0;
    
    // Get the function being called
    FunctionDeclNode* targetFunc = nullptr;
    if (funcCall->varRef && funcCall->varRef->funcNode) {
        targetFunc = funcCall->varRef->funcNode;
    }
    if (!targetFunc) {
        throw std::runtime_error("Cannot call function - no target function found");
    }
    
    // Load the function address into RBX
    auto access = funcCall->getVariableAccess();
    
    if (access.parameterIndex == -1) {
        // Function address is in current scope - load directly into RBX
        total_length += emitter.emitMovRegFromMemory(3, 15, access.offset); // mov rbx, [r15 + offset]
    } else {
        // Function address is in parent scope - load scope address from parameter, then access function
        total_length += emitter.emitMovRAXFromParam(access.parameterIndex);
        // Now load function address from [rax + offset] into RBX
        if (access.offset == 0) {
            total_length += emitter.emitBytes({0x48, 0x8B, 0x18}); // mov rbx, [rax]
        } else {
            total_length += emitter.emitBytes({0x48, 0x8B, 0x58, static_cast<uint8_t>(access.offset)}); // mov rbx, [rax + offset]
        }
    }
    
    // NEW CALLING CONVENTION:
    // 1. Push R15 (save parent scope)
    total_length += emitter.emitBytes({0x41, 0x57}); // push r15
    
    // 2. Save function address (RBX) on stack since we'll need it later
    total_length += emitter.emitBytes({0x53}); // push rbx
    
    // 3. Evaluate all arguments first and save them on stack (before changing R15)
    std::vector<size_t> arg_stack_positions;
    for (size_t i = 0; i < funcCall->args.size(); i++) {
        // Generate code to evaluate the argument (result in RAX)
        total_length += generateNode(funcCall->args[i].get(), current_scope);
        // Push argument value onto stack
        total_length += emitter.emitBytes({0x50}); // push rax
        arg_stack_positions.push_back(i);
    }
    
    // 4. Allocate scope object for target function
    // Get current brk (program break) - this will be our allocated memory
    total_length += emitter.emitMovRAXImm64(12);       // sys_brk (12)
    total_length += emitter.emitBytes({0x48, 0x31, 0xFF}); // xor rdi, rdi (0)
    total_length += emitter.emitSyscall();
    
    // Save current brk in RCX (instead of RBX to avoid conflict)
    total_length += emitter.emitBytes({0x48, 0x89, 0xC1}); // mov rcx, rax
    
    // Set new brk to current + scope size
    total_length += emitter.emitMovRAXImm64(12);       // sys_brk
    total_length += emitter.emitBytes({0x48, 0x89, 0xCA}); // mov rdx, rcx  
    total_length += emitter.emitBytes({0x48, 0x81, 0xC2}); // add rdx, imm32
    total_length += emitter.emitU32(static_cast<uint32_t>(targetFunc->totalSize));
    total_length += emitter.emitBytes({0x48, 0x89, 0xD7}); // mov rdi, rdx
    total_length += emitter.emitSyscall();
    
    // Use the old brk value as our allocated memory
    total_length += emitter.emitBytes({0x48, 0x89, 0xC8}); // mov rax, rcx
    
    // Move allocated memory address to R15 (our lexical scope pointer)
    total_length += emitter.emitMovR15RAX();
    
    // 5. Copy parameters from stack to R15+offset (in reverse order since stack is LIFO)
    int param_offset = 0;
    for (int i = funcCall->args.size() - 1; i >= 0; i--) {
        total_length += emitter.emitBytes({0x58}); // pop rax
        // Store parameter at R15+param_offset
        total_length += emitter.emitMovQwordPtrR15PlusOffsetRAX(param_offset);
        param_offset += 8;
    }
    
    // 6. Add hidden parameters for parent scopes that the function needs
    for (size_t i = 0; i < targetFunc->allNeeded.size(); i++) {
        int neededDepth = targetFunc->allNeeded[i];
        if (neededDepth != targetFunc->depth) { // Don't pass current scope to itself
            // Get the parameter index for this scope depth
            auto it = targetFunc->scopeDepthToParentParameterIndexMap.find(neededDepth);
            if (it != targetFunc->scopeDepthToParentParameterIndexMap.end()) {
                int paramIndex = it->second;
                
                if (neededDepth == current_scope->depth) {
                    // This is the current scope - pass R15 (before we changed it)
                    // We need to get the original R15 from the stack
                    // The original R15 is at [rsp + 8] (since we pushed rbx after r15)
                    total_length += emitter.emitBytes({0x48, 0x8B, 0x44, 0x24, 0x08}); // mov rax, [rsp + 8]
                } else {
                    // This scope should be passed from our parent - not implemented yet
                    // For now, just pass the current scope
                    total_length += emitter.emitBytes({0x48, 0x8B, 0x44, 0x24, 0x08}); // mov rax, [rsp + 8]
                }
                
                // Store parent scope pointer at R15+param_offset
                total_length += emitter.emitMovQwordPtrR15PlusOffsetRAX(param_offset);
                param_offset += 8;
            }
        }
    }
    
    // 7. Restore function address from stack
    total_length += emitter.emitBytes({0x5B}); // pop rbx
    
    // 7. Call the function directly (RBX contains the function address)
    total_length += emitter.emitBytes({0x48, 0x89, 0xD8}); // mov rax, rbx
    total_length += emitter.emitBytes({0xFF, 0xD0}); // call rax
    
    // 8. Restore R15 (parent scope)
    total_length += emitter.emitPopR15();
    
    return total_length;
}

size_t Codegen::generatePrintStatement(ASTNode* node, LexicalScopeNode* current_scope) {
    size_t total_length = 0;
    
    // For each argument to print, generate code to load it into RDI and call print_int64
    for (auto& child : node->children) {
        // Generate code to load the value into RAX
        total_length += generateNode(child.get(), current_scope);
        
        // Move RAX to RDI (first argument register)
        total_length += emitter.emitBytes({0x48, 0x89, 0xC7}); // mov rdi, rax
        
        // Ensure 16-byte stack alignment before calling C function
        // Check if RSP is 16-byte aligned (test bottom 4 bits)
        total_length += emitter.emitBytes({0x48, 0x83, 0xE4, 0xF0}); // and rsp, 0xFFFFFFFFFFFFFFF0 (align to 16 bytes)
        
        // Call print_int64 function
        uint64_t print_addr = extern_function_addresses["print_int64"];
        total_length += emitter.emitCallAbsolute(print_addr);
    }
    
    return total_length;
}

size_t Codegen::createClosures(LexicalScopeNode* scope) {
    size_t total_length = 0;
    
    // Loop through all variables in this scope
    for (auto& [name, varInfo] : scope->variables) {
        if (varInfo.type == DataType::CLOSURE) {
            // This is a closure variable - store function address directly
            FunctionDeclNode* funcNode = varInfo.funcNode;
            if (!funcNode) continue;
            
            // Store function address directly at R15 + offset
            // mov rax, <placeholder>
            total_length += emitter.emitBytes({0x48, 0xB8}); // mov rax, imm64 prefix
            
            // Create patch entry with exact offset
            size_t patch_offset;
            total_length += emitter.emitFunctionAddressPlaceholder(patch_offset);
            function_patches.push_back(FunctionPatch(patch_offset, funcNode));
            
            // Store function address at R15 + offset
            total_length += emitter.emitMovQwordPtrR15PlusOffsetRAX(varInfo.offset);
        }
    }
    
    return total_length;
}

void Codegen::patchFunctionAddresses() {
    // Patch all function addresses in the machine code buffer
    for (const auto& patch : function_patches) {
        uint64_t addr_to_patch;
        
        if (patch.is_string_patch) {
            // For string patches, we need to calculate absolute address in executable memory
            // This will be done in writeProgramToExecutable after we know the base address
            addr_to_patch = patch.string_offset; // Store offset for now
        } else {
            // For function patches, use the function address
            addr_to_patch = patch.func->functionAddress;
        }
        
        // Write the address into the buffer at the exact offset
        for (int i = 0; i < 8; i++) {
            emitter.buffer[patch.offset_in_buffer + i] = static_cast<uint8_t>((addr_to_patch >> (i * 8)) & 0xFF);
        }
    }
}

void Codegen::generateProgram(ASTNode& root) {
    emitter.clear();
    initExternFunctions();
    function_patches.clear();
    
    // Cast root to LexicalScopeNode (global scope)
    LexicalScopeNode* global_scope = static_cast<LexicalScopeNode*>(&root);
    
    // Setup global scope WITHOUT pushing R15 (since there's no parent scope)
    // Allocate memory for global scope
    emitter.emitMovRAXImm64(12);       // sys_brk (12)
    emitter.emitBytes({0x48, 0x31, 0xFF}); // xor rdi, rdi (0)
    emitter.emitSyscall();
    
    // Save current brk in RBX
    emitter.emitBytes({0x48, 0x89, 0xC3}); // mov rbx, rax
    
    // Set new brk to current + scope size
    emitter.emitMovRAXImm64(12);       // sys_brk
    emitter.emitBytes({0x48, 0x89, 0xD9}); // mov rcx, rbx  
    emitter.emitBytes({0x48, 0x81, 0xC1}); // add rcx, imm32
    emitter.emitU32(static_cast<uint32_t>(global_scope->totalSize));
    emitter.emitBytes({0x49, 0x89, 0xCA}); // mov r10, rcx (use R10 instead of RDI)
    emitter.emitBytes({0x4C, 0x89, 0xD7}); // mov rdi, r10 (move to RDI only for syscall)
    emitter.emitSyscall();
    emitter.emitBytes({0x4C, 0x89, 0xD1}); // mov rcx, r10 (restore rcx from r10 for later use)
    
    // Use the old brk value as our allocated memory
    emitter.emitBytes({0x48, 0x89, 0xD8}); // mov rax, rbx
    
    // Move allocated memory address to R15 (our lexical scope pointer)
    emitter.emitMovR15RAX();
    
    // Create closures for global scope
    createClosures(global_scope);
    
    // FIRST PASS: Generate main program flow (skip function definitions)
    // Main program code (skip function definitions)
    for (auto& child : global_scope->ASTNode::children) {
        if (child->type != NodeType::FUNCTION_DECL) {
            generateNode(child.get(), global_scope);
        }
    }
    
    // Add a jump to skip over function definitions
    size_t jump_over_functions = emitter.buffer.size();
    emitter.emitBytes({0xE9, 0x00, 0x00, 0x00, 0x00}); // jmp rel32 (placeholder)
    
    // SECOND PASS: Generate function definitions
    size_t functions_start = emitter.buffer.size();
    for (auto& child : global_scope->ASTNode::children) {
        if (child->type == NodeType::FUNCTION_DECL) {
            generateNode(child.get(), global_scope);
        }
    }
    
    // Calculate jump distance to skip functions and patch the jump
    size_t functions_end = emitter.buffer.size();
    int32_t jump_distance = functions_end - (jump_over_functions + 5); // +5 for jump instruction size
    
    // Patch the jump instruction
    uint8_t* jump_patch = &emitter.buffer[jump_over_functions + 1];
    jump_patch[0] = jump_distance & 0xFF;
    jump_patch[1] = (jump_distance >> 8) & 0xFF;
    jump_patch[2] = (jump_distance >> 16) & 0xFF;
    jump_patch[3] = (jump_distance >> 24) & 0xFF;
    
    // PROGRAM CONTINUATION: This is where the main program continues after the function call
    // No need to restore R15 for global scope since we never pushed it
    
    // For now, just exit cleanly
    emitter.emitMovRAXImm64(60);  // sys_exit
    emitter.emitXorRdiRdi();      // exit code 0
    emitter.emitSyscall();
}

void Codegen::writeProgramToExecutable() {
    // First, update function addresses to absolute addresses before patching
    // We need to know where functions will be located in the executable memory
    
    // Allocate executable memory
    void* exec_mem = mmap(nullptr, emitter.buffer.size(), 
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (exec_mem == MAP_FAILED) {
        std::cerr << "Failed to allocate executable memory" << std::endl;
        return;
    }

    // Convert relative addresses to absolute addresses in executable memory
    uint64_t base_address = reinterpret_cast<uint64_t>(exec_mem);
    
    // Patch all addresses (both function and string addresses) BEFORE copying to executable memory
    for (const auto& patch : function_patches) {
        uint64_t addr_to_patch;
        
        if (patch.is_string_patch) {
            // For string patches, calculate absolute address
            addr_to_patch = base_address + patch.string_offset;
        } else {
            // For function patches, calculate absolute address in executable memory
            if (patch.func == nullptr) {
                throw std::runtime_error("ERROR: Function patch has null function pointer at offset " + std::to_string(patch.offset_in_buffer));
            }
            // The function address should be base_address + relative offset in buffer
            addr_to_patch = base_address + patch.func->functionAddress;
        }
        
        // Write the address into the buffer at the exact offset
        for (int i = 0; i < 8; i++) {
            emitter.buffer[patch.offset_in_buffer + i] = static_cast<uint8_t>((addr_to_patch >> (i * 8)) & 0xFF);
        }
    }

    // Copy machine code to executable memory AFTER patching
    std::memcpy(exec_mem, emitter.buffer.data(), emitter.buffer.size());
    
    // Disassemble the patched code
    disassembleCode(emitter.buffer, base_address);
    
    // Execute the code
    typedef void (*func_ptr)();
    func_ptr func = reinterpret_cast<func_ptr>(exec_mem);
    func();
    
    // Clean up
    munmap(exec_mem, emitter.buffer.size());
}

size_t Codegen::loadVariableIntoRegister(IdentifierNode* identifier, LexicalScopeNode* current_scope, Register target_reg) {
    size_t total_length = 0;
    auto access = identifier->getVariableAccess();
    int reg_num = static_cast<int>(target_reg);
    
    // Debug output
    printf("DEBUG loadVariableIntoRegister: var='%s' paramIndex=%d offset=%d current_scope_depth=%d\n", 
           identifier->value.c_str(), access.parameterIndex, access.offset, current_scope->depth);
    if (identifier->varRef && identifier->varRef->definedIn) {
        printf("DEBUG: var defined in scope depth=%d\n", identifier->varRef->definedIn->depth);
    }
    if (identifier->accessedIn) {
        printf("DEBUG: var accessed in scope depth=%d\n", identifier->accessedIn->depth);
    }
    
    if (access.parameterIndex == -1) {
        // Variable is in current scope - load from R15+offset
        printf("DEBUG: Loading from current scope R15+%d\n", access.offset);
        
        // Load directly from R15 + offset
        total_length += emitter.emitMovRegFromMemory(reg_num, 15, access.offset); // R15 = 15
    } else {
        // Variable is in a parent scope - load scope address from function's hidden parameter area first
        printf("DEBUG: Loading from parent scope via hidden parameter %d + offset %d\n", access.parameterIndex, access.offset);
        printf("DEBUG: This should load scope pointer from R15+hidden_param_offset and then access variable\n");
        
        // Calculate where the parent scope pointer is stored in the function's parameter area
        // Hidden parameters start after regular parameters
        // For now, assume parameter 1 is stored at R15+8 (this is where we stored it)
        int hidden_param_offset = 8; // This corresponds to parameter index 1
        
        // Load the parent scope address into target register
        total_length += emitter.emitMovRegFromMemory(reg_num, 15, hidden_param_offset); // Load parent scope pointer from R15+8
        
        // Now load the variable from [target_reg + offset]
        total_length += emitter.emitMovRegFromMemory(reg_num, reg_num, access.offset);
    }
    
    return total_length;
}

void Codegen::disassembleCode(const std::vector<uint8_t>& code, uint64_t base_address) {
    csh handle;
    cs_insn *insn;
    size_t count;
    
    // Initialize capstone for x86-64
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        std::cerr << "Failed to initialize Capstone disassembler" << std::endl;
        return;
    }
    
    // Disassemble the code
    count = cs_disasm(handle, code.data(), code.size(), base_address, 0, &insn);
    
    if (count > 0) {
        std::cout << "\n=== DISASSEMBLY OF PATCHED CODE ===\n";
        std::cout << "Base address: 0x" << std::hex << base_address << std::dec << "\n";
        std::cout << "Code size: " << code.size() << " bytes\n\n";
        
        for (size_t j = 0; j < count; j++) {
            std::cout << "0x" << std::hex << insn[j].address << std::dec << ":\t";
            
            // Print hex bytes
            std::cout << std::hex;
            for (size_t k = 0; k < insn[j].size; k++) {
                std::cout << std::setfill('0') << std::setw(2) << (int)insn[j].bytes[k] << " ";
            }
            
            // Pad with spaces for alignment
            for (size_t k = insn[j].size; k < 8; k++) {
                std::cout << "   ";
            }
            
            std::cout << std::dec << "\t" << insn[j].mnemonic << "\t" << insn[j].op_str << std::endl;
        }
        
        std::cout << "\n=== END DISASSEMBLY ===\n\n";
        
        // Free memory allocated by cs_disasm()
        cs_free(insn, count);
    } else {
        std::cerr << "Failed to disassemble code" << std::endl;
    }
    
    // Close capstone handle
    cs_close(&handle);
}
