#include "codegen.h"
#include "library.h"
#include <iostream>
#include <cstring>
#include <iomanip>

void Codegen::initExternFunctions() {
    // Get addresses of extern C functions for maximum performance
    uint64_t print_addr = reinterpret_cast<uint64_t>(print_int64);
    std::cout << "DEBUG initExternFunctions: storing print_int64 at address 0x" << std::hex << print_addr << std::dec << std::endl;
    extern_function_addresses["print_int64"] = print_addr;
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
                total_length += generateClosureCall(&dummy_call, current_scope);
            } else {
                total_length += generateIdentifier(identifier);
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
            total_length += generateClosureCall(funcCall, current_scope);
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
                    total_length += generateClosureCall(&dummy_call, current_scope);
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

size_t Codegen::generateIdentifier(IdentifierNode* identifier) {
    // Use the flexible helper to load variable into RAX (maintaining backward compatibility)
    return loadVariableIntoRegister(identifier, Register::RAX);
}

size_t Codegen::generateClosureCall(FunctionCallNode* funcCall, LexicalScopeNode* current_scope) {
    size_t total_length = 0;
    
    // Get the function being called
    FunctionDeclNode* targetFunc = nullptr;
    if (funcCall->varRef && funcCall->varRef->funcNode) {
        targetFunc = funcCall->varRef->funcNode;
    }
    if (!targetFunc) {
        throw std::runtime_error("Cannot call function - no target function found");
    }
    
    // NEW CALLING CONVENTION:
    // 1. Load closure address from parent scope FIRST (while R15 is still parent scope)
    total_length += loadVariableIntoRegister(funcCall, Register::RBX);
    
    // 2. Allocate scope object for target function (keep R15 as current scope for now)
    // Get current brk (program break) - this will be our allocated memory
    total_length += emitter.emitMovRAXImm64(12);       // sys_brk (12)
    total_length += emitter.emitBytes({0x48, 0x31, 0xFF}); // xor rdi, rdi (0)
    total_length += emitter.emitSyscall();
    
    // Save current brk in RCX
    total_length += emitter.emitBytes({0x48, 0x89, 0xC1}); // mov rcx, rax
    
    // Set new brk to current + scope size
    total_length += emitter.emitMovRAXImm64(12);       // sys_brk
    total_length += emitter.emitBytes({0x48, 0x89, 0xCA}); // mov rdx, rcx  
    total_length += emitter.emitBytes({0x48, 0x81, 0xC2}); // add rdx, imm32
    total_length += emitter.emitU32(static_cast<uint32_t>(targetFunc->totalSize));
    total_length += emitter.emitBytes({0x48, 0x89, 0xD7}); // mov rdi, rdx
    total_length += emitter.emitSyscall();
    
    // Store the new scope address in R14 (R15 remains current scope for argument evaluation)
    total_length += emitter.emitBytes({0x49, 0x89, 0xCE}); // mov r14, rcx
    
    // Calculate the starting offset for hidden parameters (after regular parameters)
    int hidden_param_start_offset = 0;
    for (const std::string& paramName : targetFunc->params) {
        auto paramIt = targetFunc->variables.find(paramName);
        if (paramIt != targetFunc->variables.end()) {
            int param_end = paramIt->second.offset + paramIt->second.size;
            if (param_end > hidden_param_start_offset) {
                hidden_param_start_offset = param_end;
            }
        }
    }
    // Align to 8 bytes
    hidden_param_start_offset = (hidden_param_start_offset + 7) & ~7;
    
    // 3. Evaluate arguments and store them directly at their correct offsets in the new scope
    // R15 = current scope (for evaluating arguments), R14 = new scope (for storing results)
    for (size_t i = 0; i < funcCall->args.size(); i++) {
        // Generate code to evaluate the argument (result in RAX) using current scope (R15)
        total_length += generateNode(funcCall->args[i].get(), current_scope);
        
        // Find the parameter name and get its offset from the target function
        std::string paramName = targetFunc->params[i];
        auto paramIt = targetFunc->variables.find(paramName);
        if (paramIt != targetFunc->variables.end()) {
            int paramOffset = paramIt->second.offset;
            // Store argument directly at [R14 + paramOffset] (R14 contains new scope address)
            total_length += emitter.emitBytes({0x49, 0x89, 0x86}); // mov [r14 + offset], rax
            total_length += emitter.emitU32(static_cast<uint32_t>(paramOffset));
        } else {
            throw std::runtime_error("Parameter not found in target function: " + paramName);
        }
    }
    
    // 4. Copy hidden lexical scope parameters from closure to their proper offsets
    // IMPORTANT: Do this BEFORE switching R15, while we still have access to parent scope
    
    // Load closure address into RCX and keep it there throughout the loop
    printf("DEBUG: About to call loadVariableDefiningScopeAddressIntoRegister with RCX\n");
    total_length += loadVariableDefiningScopeAddressIntoRegister(funcCall, Register::RCX);
    printf("DEBUG: Finished loadVariableDefiningScopeAddressIntoRegister\n");
    auto variable_offset = funcCall->getVariableAccess().offset;
    
    printf("DEBUG: targetFunc->allNeeded.size() = %zu\n", targetFunc->allNeeded.size());
    // Copy each lexical scope address from closure to new scope
    for (size_t i = 0; i < targetFunc->allNeeded.size(); i++) {
        printf("DEBUG: Processing allNeeded[%zu]\n", i);
        // Load scope pointer from closure structure at offset 8 + (i * 8)
        size_t scope_offset_in_closure = 8 + (i * 8);
        auto total_offset = scope_offset_in_closure + variable_offset;
        
        // Load the scope pointer from [rcx + total_offset] into RAX
        total_length += emitter.emitMovRAXFromRCXPlusOffset(static_cast<uint32_t>(total_offset));
        
        // Store in new scope at hidden parameter offset
        int hidden_param_offset = hidden_param_start_offset + (i * 8);
        total_length += emitter.emitMovQwordPtrR14PlusOffsetRAX(static_cast<uint32_t>(hidden_param_offset));
    }
    
    // 5. Push R15 (save parent scope) and switch to new scope
    total_length += emitter.emitBytes({0x41, 0x57}); // push r15
    total_length += emitter.emitBytes({0x4D, 0x89, 0xF7}); // mov r15, r14
    
    // 6. Load function address from closure (now in RCX) and call
    // Function address is at closure base (offset 0)
    // RCX contains closure address from loadVariableDefiningScopeAddressIntoRegister call
    total_length += emitter.emitBytes({0x48, 0x8B, 0x01}); // mov rax, [rcx]
    
    // Call the function
    total_length += emitter.emitBytes({0xFF, 0xD0}); // call rax
    
    // 7. Restore R15 (parent scope)
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
        
        // NOTE: Stack alignment removed - caller should ensure proper alignment
        // The stack alignment was corrupting the return address in functions
        
        // Call print_int64 function
        uint64_t print_addr = extern_function_addresses["print_int64"];
        std::cout << "DEBUG generatePrintStatement: retrieved print_int64 address 0x" << std::hex << print_addr << std::dec << std::endl;
        total_length += emitter.emitCallAbsolute(print_addr);
    }
    
    return total_length;
}

size_t Codegen::createClosures(LexicalScopeNode* scope) {
    size_t total_length = 0;
    
    // Loop through all variables in this scope
    for (auto& [name, varInfo] : scope->variables) {
        if (varInfo.type == DataType::CLOSURE) {
            // This is a closure variable - store the closure structure DIRECTLY in the variable slots
            FunctionDeclNode* funcNode = varInfo.funcNode;
            if (!funcNode) continue;
            
            // Store function address directly at R15 + varInfo.offset (first 8 bytes of closure)
            // mov rax, <placeholder>
            total_length += emitter.emitBytes({0x48, 0xB8}); // mov rax, imm64 prefix
            
            // Create patch entry with exact offset
            size_t patch_offset;
            total_length += emitter.emitFunctionAddressPlaceholder(patch_offset);
            function_patches.push_back(FunctionPatch(patch_offset, funcNode));
            
            // Store function address at R15 + varInfo.offset
            total_length += emitter.emitMovQwordPtrR15PlusOffsetRAX(varInfo.offset);
            
            // Now store addresses of needed parent scopes immediately after the function address
            // For each scope in funcNode->allNeeded, we need to store its address
            for (size_t i = 0; i < funcNode->allNeeded.size(); i++) {
                int neededDepth = funcNode->allNeeded[i];
                
                // Get parameter index for this scope depth
                auto it = funcNode->scopeDepthToParentParameterIndexMap.find(neededDepth);
                if (it != funcNode->scopeDepthToParentParameterIndexMap.end()) {
                    int absoluteParamIndex = it->second;
                    
                    // Load scope address using absolute parameter index directly
                    // Convert absolute parameter index to byte offset
                    printf("DEBUG: Creating closure - loading scope for depth %d from absolute param %d (offset %d)\n", neededDepth, absoluteParamIndex);
                    
                    if (absoluteParamIndex == -1) {
                        // Special case: current scope (R15)
                        total_length += emitter.emitBytes({0x4C, 0x89, 0xF8}); // mov rax, r15
                    } else {
                        // Load from parameter at absolute offset
                        int param_offset = 8 * absoluteParamIndex;
                        printf("PARAM OFFSET: %d\n", param_offset);
                        total_length += emitter.emitMovRAXFromR15Offset(param_offset);
                    }
                } else {
                    // Scope not found in parameter map - this is an error
                    throw std::runtime_error("Scope dependency not found: function '" + 
                                           funcNode->funcName + "' needs scope at depth " + 
                                           std::to_string(neededDepth) + " but no parameter mapping exists");
                }
                
                // Store the scope address immediately after function address
                // Closure structure: [func_addr at offset][scope1 at offset+8][scope2 at offset+16]...
                size_t scope_offset = varInfo.offset + 8 + (i * 8);
                total_length += emitter.emitMovQwordPtrR15PlusOffsetRAX(scope_offset);
            }
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
    
    // NOW patch all function addresses in the closures
    patchFunctionAddresses();
    
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

size_t Codegen::loadVariableIntoRegister(IdentifierNode* identifier, Register target_reg) {
    size_t total_length = 0;
    
    // Ensure accessedIn is properly set during analysis
    if (!identifier->accessedIn) {
        throw std::runtime_error("Variable access scope not set during analysis: " + identifier->value);
    }
    
    auto access = identifier->getVariableAccess();
    int reg_num = static_cast<int>(target_reg);
    
    // Debug output
    printf("DEBUG loadVariableIntoRegister: var='%s' paramIndex=%d paramOffset=%d offset=%d\n", 
           identifier->value.c_str(), access.parameterIndex, access.parameterOffset, access.offset);
    if (identifier->varRef && identifier->varRef->definedIn) {
        printf("DEBUG: var defined in scope depth=%d\n", identifier->varRef->definedIn->depth);
    }
    if (identifier->accessedIn) {
        printf("DEBUG: var accessed in scope depth=%d\n", identifier->accessedIn->depth);
    }
    
    if (access.parameterIndex == -1) {
        // Variable is in current scope - load from R15+offset
        printf("DEBUG: Loading from current scope R15+%d\n", access.offset);
        
        // Use general method for all registers (simplified and consistent)
        total_length += emitter.emitMovRegFromMemory(reg_num, 15, access.offset); // R15 = 15
    } else {
        // Variable is in a parent scope - load scope address from hidden parameter
        printf("DEBUG: Loading from parent scope via parameter offset %d + variable offset %d\n", access.parameterOffset, access.offset);
        
        // Use the pre-calculated parameter offset directly (accounts for variable-sized parameters)
        printf("DEBUG: Using parameter offset: %d\n", access.parameterOffset);
        
        // Load the parent scope address from parameter, then load the variable
        // Use general method for all registers (simplified and consistent)
        total_length += emitter.emitMovRegFromMemory(reg_num, 15, access.parameterOffset);
        total_length += emitter.emitMovRegFromMemory(reg_num, reg_num, access.offset);
    }
    
    return total_length;
}

size_t Codegen::loadVariableDefiningScopeAddressIntoRegister(IdentifierNode* identifier, Register target_reg) {
    size_t total_length = 0;
    
    // Ensure accessedIn is properly set during analysis
    if (!identifier->accessedIn) {
        throw std::runtime_error("Variable access scope not set during analysis: " + identifier->value);
    }
    
    auto access = identifier->getVariableAccess();
    int reg_num = static_cast<int>(target_reg);
    
    // Debug output
    printf("DEBUG loadVariableDefiningScopeAddressIntoRegister: var='%s' paramIndex=%d paramOffset=%d\n", 
           identifier->value.c_str(), access.parameterIndex, access.parameterOffset);
    if (identifier->varRef && identifier->varRef->definedIn) {
        printf("DEBUG: var defined in scope depth=%d\n", identifier->varRef->definedIn->depth);
    }
    if (identifier->accessedIn) {
        printf("DEBUG: var accessed in scope depth=%d\n", identifier->accessedIn->depth);
    }
    
    if (access.parameterIndex == -1) {
        // Variable is in current scope - load R15 (current scope address) into target register
        printf("DEBUG: Loading current scope address from R15\n");
        printf("DEBUG: target_reg = %d, Register::R15 = %d\n", (int)target_reg, (int)Register::R15);
        
        // Move R15 to target register
        if (target_reg == Register::R15) {
            // No need to move if target is already R15
            printf("DEBUG: Target register is already R15, no move needed\n");
        } else {
            printf("DEBUG: Target register is NOT R15, calling emitMovRegFromReg\n");
            total_length += emitter.emitMovRegFromReg(reg_num, 15); // Move R15 to target register
        }
    } else {
        // Variable is in a parent scope - load the parent scope address from hidden parameter
        printf("DEBUG: Loading parent scope address from parameter offset %d\n", access.parameterOffset);
        
        // Use the pre-calculated parameter offset directly (accounts for variable-sized parameters)
        printf("DEBUG: Using parameter offset: %d\n", access.parameterOffset);
        
        // Load the parent scope address from parameter
        total_length += emitter.emitMovRegFromMemory(reg_num, 15, access.parameterOffset);
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
