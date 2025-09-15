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
            
            printf("DEBUG: === STARTING code generation for function '%s' at depth=%d ===\n", 
                   funcDecl->funcName.c_str(), funcDecl->depth);
            
            // Set the function address to current position in buffer
            funcDecl->functionAddress = emitter.buffer.size();
            printf("DEBUG: Function '%s' assigned address offset 0x%lx\n", funcDecl->funcName.c_str(), funcDecl->functionAddress);
            
            printf("DEBUG: === STARTING function prologue for '%s' ===\n", funcDecl->funcName.c_str());
            printf("DEBUG: Function has %zu regular params and %zu hidden params\n", 
                   funcDecl->params.size(), funcDecl->hiddenParamsInfo.size());
            
            // NEW STANDARD ABI CALLING CONVENTION PROLOGUE:
            // 1. Standard function prologue
            total_length += emitter.emitBytes({0x55}); // push rbp
            total_length += emitter.emitBytes({0x48, 0x89, 0xE5}); // mov rbp, rsp
            
            // 2. First, save all parameter registers to the stack before we allocate scope
            // This prevents them from being corrupted during heap allocation
            printf("DEBUG: Saving parameter registers before heap allocation\n");
            total_length += emitter.emitBytes({0x57}); // push rdi
            total_length += emitter.emitBytes({0x56}); // push rsi  
            total_length += emitter.emitBytes({0x52}); // push rdx
            total_length += emitter.emitBytes({0x51}); // push rcx
            total_length += emitter.emitBytes({0x41, 0x50}); // push r8
            total_length += emitter.emitBytes({0x41, 0x51}); // push r9
            
            // 3. Allocate lexical scope for this function (now safe to use registers)
            printf("DEBUG: Allocating heap memory for function scope (size=%d)\n", funcDecl->totalSize);
            total_length += emitter.emitMovRAXImm64(12);       // sys_brk (12)
            total_length += emitter.emitBytes({0x48, 0x31, 0xFF}); // xor rdi, rdi (0)
            total_length += emitter.emitSyscall();
            
            // Save current brk in RBX (non-parameter register)
            total_length += emitter.emitBytes({0x48, 0x89, 0xC3}); // mov rbx, rax
            
            // Set new brk to current + scope size
            total_length += emitter.emitMovRAXImm64(12);       // sys_brk
            total_length += emitter.emitBytes({0x48, 0x89, 0xDA}); // mov rdx, rbx  
            total_length += emitter.emitBytes({0x48, 0x81, 0xC2}); // add rdx, imm32
            total_length += emitter.emitU32(static_cast<uint32_t>(funcDecl->totalSize));
            total_length += emitter.emitBytes({0x48, 0x89, 0xD7}); // mov rdi, rdx
            total_length += emitter.emitSyscall();
            
            // Set R15 to allocated scope (old brk value in RBX)
            total_length += emitter.emitBytes({0x49, 0x89, 0xDF}); // mov r15, rbx
            
            // 4. Now restore parameter registers from stack and copy to lexical scope
            // Restore in reverse order
            total_length += emitter.emitBytes({0x41, 0x59}); // pop r9
            total_length += emitter.emitBytes({0x41, 0x58}); // pop r8
            total_length += emitter.emitBytes({0x59}); // pop rcx
            total_length += emitter.emitBytes({0x5A}); // pop rdx
            total_length += emitter.emitBytes({0x5E}); // pop rsi
            total_length += emitter.emitBytes({0x5F}); // pop rdi
            
            // 3. Copy parameters from standard calling convention to lexical scope
            // Standard x86-64 calling convention registers: RDI, RSI, RDX, RCX, R8, R9
            
            size_t total_params = funcDecl->params.size() + funcDecl->hiddenParamsInfo.size();
            
            // Copy regular parameters first
            for (size_t i = 0; i < funcDecl->params.size(); i++) {
                const std::string& paramName = funcDecl->params[i];
                auto paramIt = funcDecl->variables.find(paramName);
                if (paramIt == funcDecl->variables.end()) {
                    throw std::runtime_error("Parameter not found in function variables: " + paramName);
                }
                int paramOffset = paramIt->second.offset;
                
                printf("DEBUG: Copying parameter %zu ('%s') to offset %d\n", i, paramName.c_str(), paramOffset);
                
                if (i < 6) { // First 6 parameters come in registers
                    // Copy parameter from register to R15+offset
                    switch(i) {
                        case 0: // RDI
                            printf("DEBUG: Copying from RDI to R15+%d\n", paramOffset);
                            total_length += emitter.emitBytes({0x49, 0x89, 0xBF}); // mov [r15 + disp32], rdi
                            total_length += emitter.emitU32(static_cast<uint32_t>(paramOffset));
                            break;
                        case 1: // RSI  
                            printf("DEBUG: Copying from RSI to R15+%d\n", paramOffset);
                            total_length += emitter.emitBytes({0x49, 0x89, 0xB7}); // mov [r15 + disp32], rsi
                            total_length += emitter.emitU32(static_cast<uint32_t>(paramOffset));
                            break;
                        case 2: // RDX
                            total_length += emitter.emitBytes({0x49, 0x89, 0x97}); // mov [r15 + disp32], rdx
                            total_length += emitter.emitU32(static_cast<uint32_t>(paramOffset));
                            break;
                        case 3: // RCX
                            total_length += emitter.emitBytes({0x49, 0x89, 0x8F}); // mov [r15 + disp32], rcx
                            total_length += emitter.emitU32(static_cast<uint32_t>(paramOffset));
                            break;
                        case 4: // R8
                            total_length += emitter.emitBytes({0x4D, 0x89, 0x87}); // mov [r15 + disp32], r8
                            total_length += emitter.emitU32(static_cast<uint32_t>(paramOffset));
                            break;
                        case 5: // R9
                            total_length += emitter.emitBytes({0x4D, 0x89, 0x8F}); // mov [r15 + disp32], r9
                            total_length += emitter.emitU32(static_cast<uint32_t>(paramOffset));
                            break;
                    }
                } else {
                    // Parameter came on stack - load from stack and store to lexical scope
                    size_t stack_offset = 16 + ((i - 6) * 8); // Skip saved rbp + return addr
                    // mov rax, [rbp + stack_offset]
                    total_length += emitter.emitBytes({0x48, 0x8B, 0x85}); // mov rax, [rbp + offset]
                    total_length += emitter.emitU32(static_cast<uint32_t>(stack_offset));
                    // mov [r15 + paramOffset], rax
                    total_length += emitter.emitBytes({0x49, 0x89, 0x87}); // mov [r15 + offset], rax
                    total_length += emitter.emitU32(static_cast<uint32_t>(paramOffset));
                }
            }
            
            // Copy hidden scope parameters
            for (size_t i = 0; i < funcDecl->hiddenParamsInfo.size(); i++) {
                size_t param_index = funcDecl->params.size() + i;
                int scopeOffset = funcDecl->hiddenParamsInfo[i].offset;
                
                printf("DEBUG: Copying hidden parameter %zu (total param index %zu) to offset %d\n", 
                       i, param_index, scopeOffset);
                
                if (param_index < 6) { // First 6 total parameters come in registers
                    // Scope address came in register - copy to lexical scope
                    switch(param_index) {
                        case 0: // RDI
                            printf("DEBUG: Copying scope from RDI to R15+%d\n", scopeOffset);
                            total_length += emitter.emitBytes({0x49, 0x89, 0xBF}); // mov [r15 + disp32], rdi
                            total_length += emitter.emitU32(static_cast<uint32_t>(scopeOffset));
                            break;
                        case 1: // RSI  
                            total_length += emitter.emitBytes({0x49, 0x89, 0xB7}); // mov [r15 + disp32], rsi
                            total_length += emitter.emitU32(static_cast<uint32_t>(scopeOffset));
                            break;
                        case 2: // RDX
                            total_length += emitter.emitBytes({0x49, 0x89, 0x97}); // mov [r15 + disp32], rdx
                            total_length += emitter.emitU32(static_cast<uint32_t>(scopeOffset));
                            break;
                        case 3: // RCX
                            total_length += emitter.emitBytes({0x49, 0x89, 0x8F}); // mov [r15 + disp32], rcx
                            total_length += emitter.emitU32(static_cast<uint32_t>(scopeOffset));
                            break;
                        case 4: // R8
                            total_length += emitter.emitBytes({0x4D, 0x89, 0x87}); // mov [r15 + disp32], r8
                            total_length += emitter.emitU32(static_cast<uint32_t>(scopeOffset));
                            break;
                        case 5: // R9
                            total_length += emitter.emitBytes({0x4D, 0x89, 0x8F}); // mov [r15 + disp32], r9
                            total_length += emitter.emitU32(static_cast<uint32_t>(scopeOffset));
                            break;
                    }
                } else {
                    // Scope address came on stack
                    size_t stack_offset = 16 + ((param_index - 6) * 8);
                    // mov rax, [rbp + stack_offset]
                    total_length += emitter.emitBytes({0x48, 0x8B, 0x85}); // mov rax, [rbp + offset]
                    total_length += emitter.emitU32(static_cast<uint32_t>(stack_offset));
                    // mov [r15 + scopeOffset], rax
                    total_length += emitter.emitBytes({0x49, 0x89, 0x87}); // mov [r15 + offset], rax
                    total_length += emitter.emitU32(static_cast<uint32_t>(scopeOffset));
                }
            }
            
            // 4. Create closures for functions defined in this scope (hoisting)
            printf("DEBUG: Creating closures for function '%s' scope\n", funcDecl->funcName.c_str());
            total_length += createClosures(funcDecl);
            
            // 5. Generate function body (children of this node)
            // Parameters are now in R15+offset lexical scope
            for (auto& child : funcDecl->ASTNode::children) {
                total_length += generateNode(child.get(), funcDecl);
            }
            
            printf("DEBUG: === FINISHED code generation for function '%s' at depth=%d ===\n", 
                   funcDecl->funcName.c_str(), funcDecl->depth);
            
            // 6. Standard epilogue (no R15 restoration needed)
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
    printf("DEBUG generateLiteral: Loading literal value %ld into RAX\n", value);
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
    
    printf("DEBUG: generateClosureCall - calling function '%s' with %zu args, %zu hidden params\n", 
           targetFunc->funcName.c_str(), funcCall->args.size(), targetFunc->hiddenParamsInfo.size());
    
    // NEW STANDARD ABI CALLING CONVENTION:
    // Place parameters in registers: RDI, RSI, RDX, RCX, R8, R9, then stack
    // Order: regular parameters first, then hidden scope parameters
    
    size_t total_params = funcCall->args.size() + targetFunc->hiddenParamsInfo.size();
    std::vector<size_t> stack_params; // For parameters beyond 6
    
    // Generate all regular parameter values and place them in registers/stack
    for (size_t i = 0; i < funcCall->args.size(); i++) {
        printf("DEBUG: Processing regular parameter %zu\n", i);
        // Generate code to evaluate the argument (result in RAX)
        total_length += generateNode(funcCall->args[i].get(), current_scope);
        
        if (i < 6) { // First 6 parameters go in registers
            switch(i) {
                case 0: // RDI
                    printf("DEBUG: Moving parameter %zu from RAX to RDI\n", i);
                    total_length += emitter.emitBytes({0x48, 0x89, 0xC7}); // mov rdi, rax
                    break;
                case 1: // RSI
                    printf("DEBUG: Moving parameter %zu from RAX to RSI\n", i);
                    total_length += emitter.emitBytes({0x48, 0x89, 0xC6}); // mov rsi, rax
                    break;
                case 2: // RDX
                    printf("DEBUG: Moving parameter %zu from RAX to RDX\n", i);
                    total_length += emitter.emitBytes({0x48, 0x89, 0xC2}); // mov rdx, rax
                    break;
                case 3: // RCX
                    printf("DEBUG: Moving parameter %zu from RAX to RCX\n", i);
                    total_length += emitter.emitBytes({0x48, 0x89, 0xC1}); // mov rcx, rax
                    break;
                case 4: // R8
                    printf("DEBUG: Moving parameter %zu from RAX to R8\n", i);
                    total_length += emitter.emitBytes({0x49, 0x89, 0xC0}); // mov r8, rax
                    break;
                case 5: // R9
                    printf("DEBUG: Moving parameter %zu from RAX to R9\n", i);
                    total_length += emitter.emitBytes({0x49, 0x89, 0xC1}); // mov r9, rax
                    break;
            }
        } else {
            // Push onto stack for later (we'll push in reverse order)
            printf("DEBUG: Parameter %zu will go on stack\n", i);
            stack_params.push_back(i);
        }
    }
    
    // Now handle hidden scope parameters (they come after regular parameters)
    // Load closure defining scope address first
    total_length += loadVariableDefiningScopeAddressIntoRegister(funcCall, Register::R10);
    auto variable_offset = funcCall->getVariableAccess().offset;
    
    for (size_t i = 0; i < targetFunc->hiddenParamsInfo.size(); i++) {
        size_t param_index = funcCall->args.size() + i;
        printf("DEBUG: Processing hidden parameter %zu (total param index %zu)\n", i, param_index);
        
        // Load scope address from closure structure
        size_t scope_offset_in_closure = 8 + (i * 8); // Function addr at 0, scopes at 8, 16, 24...
        auto total_offset = scope_offset_in_closure + variable_offset;
        
        printf("DEBUG: Loading hidden param %zu: closure offset=%zu, variable_offset=%zu, total_offset=%zu\n", 
               i, scope_offset_in_closure, variable_offset, total_offset);
        
        // Load scope address into RAX
        total_length += emitter.emitMovRAXFromR10PlusOffset(static_cast<uint32_t>(total_offset));
        
        if (param_index < 6) { // First 6 total parameters go in registers
            switch(param_index) {
                case 0: // RDI
                    printf("DEBUG: Moving hidden param %zu from RAX to RDI\n", i);
                    total_length += emitter.emitBytes({0x48, 0x89, 0xC7}); // mov rdi, rax
                    break;
                case 1: // RSI
                    printf("DEBUG: Moving hidden param %zu from RAX to RSI\n", i);
                    total_length += emitter.emitBytes({0x48, 0x89, 0xC6}); // mov rsi, rax
                    break;
                case 2: // RDX
                    printf("DEBUG: Moving hidden param %zu from RAX to RDX\n", i);
                    total_length += emitter.emitBytes({0x48, 0x89, 0xC2}); // mov rdx, rax
                    break;
                case 3: // RCX
                    printf("DEBUG: Moving hidden param %zu from RAX to RCX\n", i);
                    total_length += emitter.emitBytes({0x48, 0x89, 0xC1}); // mov rcx, rax
                    break;
                case 4: // R8
                    printf("DEBUG: Moving hidden param %zu from RAX to R8\n", i);
                    total_length += emitter.emitBytes({0x49, 0x89, 0xC0}); // mov r8, rax
                    break;
                case 5: // R9
                    printf("DEBUG: Moving hidden param %zu from RAX to R9\n", i);
                    total_length += emitter.emitBytes({0x49, 0x89, 0xC1}); // mov r9, rax
                    break;
            }
        } else {
            // Push onto stack (will be handled below)
            printf("DEBUG: Hidden parameter %zu will go on stack\n", i);
            // We'll need to save this for stack pushing - for now, push immediately
            total_length += emitter.emitBytes({0x50}); // push rax
        }
    }
    
    // TODO: Handle stack parameters (for functions with more than 6 total parameters)
    // For now, we'll assume all functions have <= 6 parameters
    
    // Load function address from closure and call
    // Use the closure address already loaded in R10
    total_length += emitter.emitMovRAXFromR10PlusOffset(static_cast<uint32_t>(variable_offset)); // Function address at closure base
    
    printf("DEBUG: About to call function\n");
    // Call the function 
    total_length += emitter.emitBytes({0xFF, 0xD0}); // call rax
    
    // TODO: Clean up stack if we used it (not needed for <= 6 params)
    
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
    
    printf("DEBUG createClosures: Starting for scope at depth %d, type=%d\n", scope->depth, (int)scope->type);
    printf("DEBUG createClosures: Scope has %zu variables\n", scope->variables.size());
    
    // Loop through all variables in this scope
    for (auto& [name, varInfo] : scope->variables) {
        printf("DEBUG createClosures: Processing variable '%s', type=%d\n", name.c_str(), (int)varInfo.type);
        
        if (varInfo.type == DataType::CLOSURE) {
            printf("DEBUG createClosures: Creating closure for function '%s'\n", name.c_str());
            
            // This is a closure variable - store the closure structure DIRECTLY in the variable slots
            FunctionDeclNode* funcNode = varInfo.funcNode;
            if (!funcNode) {
                printf("ERROR createClosures: Closure variable '%s' has no function node\n", name.c_str());
                continue;
            }
            
            printf("DEBUG createClosures: Function '%s' needs %zu parent scopes\n", funcNode->funcName.c_str(), funcNode->allNeeded.size());
            
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
            printf("DEBUG createClosures: Storing %zu parent scope addresses for function '%s'\n", funcNode->allNeeded.size(), funcNode->funcName.c_str());
            
            for (size_t i = 0; i < funcNode->allNeeded.size(); i++) {
                int neededDepth = funcNode->allNeeded[i];
                
                printf("DEBUG createClosures: Processing scope dependency %zu/%zu: depth=%d\n", i+1, funcNode->allNeeded.size(), neededDepth);
                
                // Get parameter index for this scope depth
                auto it = funcNode->scopeDepthToParentParameterIndexMap.find(neededDepth);
                if (it != funcNode->scopeDepthToParentParameterIndexMap.end()) {
                    int absoluteParamIndex = it->second;
                    
                    printf("DEBUG createClosures: Found parameter mapping: depth %d -> absolute param index %d\n", neededDepth, absoluteParamIndex);
                    
                    // Load scope address using proper parameter offset calculation
                    printf("DEBUG createClosures: Creating closure - loading scope for depth %d from absolute param %d\n", neededDepth, absoluteParamIndex);
                    
                    if (absoluteParamIndex == -1) {
                        // Special case: current scope (R15)
                        printf("DEBUG createClosures: Using current scope (R15) for depth %d\n", neededDepth);
                        total_length += emitter.emitBytes({0x4C, 0x89, 0xF8}); // mov rax, r15
                    } else {
                        // During closure creation, we need to get the scope from the current context
                        // The parameter mapping tells us where the target function will expect the scope,
                        // but we need to get it from where it currently is
                        
                        if (neededDepth == scope->depth) {
                            // If the needed scope is the current scope, use R15
                            printf("DEBUG: Storing current scope (R15) for depth %d\n", neededDepth);
                            total_length += emitter.emitBytes({0x4C, 0x89, 0xF8}); // mov rax, r15
                        } else {
                            // For parent scopes, we need to load from the current function's parameters
                            // Find the current function scope with cycle detection
                            printf("DEBUG createClosures: Looking for parent function scope from depth %d\n", scope->depth);
                            LexicalScopeNode* currentFunc = scope;
                            std::set<LexicalScopeNode*> visited;
                            int traversal_count = 0;
                            printf("DEBUG createClosures: Starting scope traversal from depth %d to find parent function\n", scope->depth);
                            
                            while (currentFunc && currentFunc->type != NodeType::FUNCTION_DECL) {
                                traversal_count++;
                                printf("DEBUG createClosures: Traversal step %d - checking scope at %p, depth=%d, type=%d\n", 
                                       traversal_count, currentFunc, currentFunc->depth, (int)currentFunc->type);
                                
                                // Cycle detection
                                if (visited.find(currentFunc) != visited.end()) {
                                    printf("ERROR createClosures: CYCLE DETECTED! Scope %p already visited\n", currentFunc);
                                    throw std::runtime_error("Closure creation error: cycle detected in scope hierarchy while looking for parent function from scope at depth " + 
                                                           std::to_string(scope->depth));
                                }
                                visited.insert(currentFunc);
                                
                                printf("DEBUG createClosures: Traversing from scope depth %d to parent at %p\n", currentFunc->depth, currentFunc->parentFunctionScope);
                                
                                if (!currentFunc->parentFunctionScope) {
                                    printf("WARNING createClosures: No parent function scope found - reached end of chain\n");
                                    break;
                                }
                                
                                currentFunc = currentFunc->parentFunctionScope;
                                
                                // Additional safety check - prevent excessive traversal
                                if (traversal_count > 20) {
                                    printf("ERROR createClosures: Excessive traversal (>20) detected - possible infinite loop\n");
                                    throw std::runtime_error("Closure creation error: excessive scope traversal (>20 levels) - possible infinite loop from scope at depth " + 
                                                           std::to_string(scope->depth));
                                }
                            }
                            
                            printf("DEBUG createClosures: Traversal completed after %d steps\n", traversal_count);
                            printf("DEBUG createClosures: Found function scope at depth %d (type=%d)\n", 
                                   currentFunc ? currentFunc->depth : -1, 
                                   currentFunc ? (int)currentFunc->type : -1);
                            
                            if (currentFunc && currentFunc->type == NodeType::FUNCTION_DECL) {
                                // Get the parameter index for this scope in the current function's context
                                auto it = currentFunc->scopeDepthToParentParameterIndexMap.find(neededDepth);
                                if (it != currentFunc->scopeDepthToParentParameterIndexMap.end()) {
                                    int currentFuncParamIndex = it->second;
                                    if (currentFuncParamIndex == -1) {
                                        printf("DEBUG: Storing current scope (R15) for depth %d via param index -1\n", neededDepth);
                                        total_length += emitter.emitBytes({0x4C, 0x89, 0xF8}); // mov rax, r15
                                    } else {
                                        int param_offset = currentFunc->getParameterOffset(currentFuncParamIndex);
                                        printf("DEBUG: Loading scope for depth %d from param offset %d\n", neededDepth, param_offset);
                                        total_length += emitter.emitMovRAXFromR15Offset(param_offset);
                                        // Add debug to print the loaded address
                                        printf("DEBUG: About to store scope address for depth %d in closure\n", neededDepth);
                                    }
                                } else {
                                    // This should not happen - throw an error instead of using fallback
                                    throw std::runtime_error("Closure creation error: scope depth " + 
                                                           std::to_string(neededDepth) + " not found in current function's parameter map");
                                }
                            } else {
                                // BUG FIX: This should be an error, not a fallback to R15
                                // If we reach here, it means we're trying to access a scope that's not available
                                // in the current context, which indicates a bug in scope dependency analysis
                                printf("ERROR: Cannot find parent function scope for closure creation\n");
                                printf("ERROR: Current scope depth=%d, type=%d\n", scope->depth, (int)scope->type);
                                printf("ERROR: Looking for needed depth=%d\n", neededDepth);
                                printf("ERROR: Visited scopes during traversal:\n");
                                for (auto* visitedScope : visited) {
                                    printf("ERROR:   - Scope at %p, depth=%d, type=%d\n", visitedScope, visitedScope->depth, (int)visitedScope->type);
                                }
                                
                                throw std::runtime_error("Closure creation error: cannot access scope at depth " + 
                                                       std::to_string(neededDepth) + " from scope at depth " + 
                                                       std::to_string(scope->depth) + ". " +
                                                       "No parent function scope found after traversing " + 
                                                       std::to_string(visited.size()) + " scopes. " +
                                                       "This indicates a bug in scope dependency analysis for function '" + 
                                                       funcNode->funcName + "'");
                            }
                        }
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
                printf("DEBUG createClosures: Storing scope for depth %d at closure offset %zu\n", neededDepth, scope_offset);
                total_length += emitter.emitMovQwordPtrR15PlusOffsetRAX(scope_offset);
            }
        }
    }
    
    return total_length;
}

void Codegen::patchFunctionAddresses() {
    printf("DEBUG patchFunctionAddresses: Patching %zu function addresses\n", function_patches.size());
    
    // Patch all function addresses in the machine code buffer
    for (const auto& patch : function_patches) {
        uint64_t addr_to_patch;
        
        if (patch.is_string_patch) {
            // For string patches, we need to calculate absolute address in executable memory
            // This will be done in writeProgramToExecutable after we know the base address
            addr_to_patch = patch.string_offset; // Store offset for now
            printf("DEBUG patchFunctionAddresses: String patch at offset %zu\n", patch.offset_in_buffer);
        } else {
            // For function patches, use the function address
            addr_to_patch = patch.func->functionAddress;
            printf("DEBUG patchFunctionAddresses: Function patch for '%s' at offset %zu, address 0x%lx\n", 
                   patch.func->funcName.c_str(), patch.offset_in_buffer, addr_to_patch);
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
    
    // Debug output with call stack info
    printf("DEBUG loadVariableIntoRegister: var='%s' paramIndex=%d\n", 
           identifier->value.c_str(), access.parameterIndex);
    
    // Additional debug for parameter index calculation
    if (identifier->varRef && identifier->varRef->definedIn && identifier->accessedIn) {
        LexicalScopeNode* definingScope = identifier->varRef->definedIn;
        LexicalScopeNode* accessingScope = identifier->accessedIn;
        printf("DEBUG: node=%p, definingScope=%p (depth=%d), accessingScope=%p (depth=%d)\n", 
               identifier, definingScope, definingScope->depth, accessingScope, accessingScope->depth);
        if (definingScope != accessingScope) {
            printf("DEBUG: Should use parent scope access - checking parameter index map\n");
            auto& paramMap = accessingScope->scopeDepthToParentParameterIndexMap;
            printf("DEBUG: Parameter map size: %zu\n", paramMap.size());
            for (auto& pair : paramMap) {
                printf("DEBUG: depth %d -> param index %d\n", pair.first, pair.second);
            }
        }
    }
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
        printf("DEBUG: About to load scope address from R15+%d\n", access.parameterOffset);
        total_length += emitter.emitMovRegFromMemory(reg_num, 15, access.parameterOffset);
        printf("DEBUG: About to load variable from scope+%d\n", access.offset);
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
    printf("\n=== ASSEMBLY DISASSEMBLY ===\n");
    printf("Base address: 0x%016lx\n", base_address);
    printf("Code size: %zu bytes\n\n", code.size());
    
    csh handle;
    cs_insn *insn;
    size_t count;
    
    // Initialize Capstone for x86-64
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        printf("ERROR: Failed to initialize Capstone disassembler\n");
        return;
    }
    
    // Disassemble the code
    count = cs_disasm(handle, code.data(), code.size(), base_address, 0, &insn);
    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
            printf("0x%016lx: %-10s %s\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
        }
        cs_free(insn, count);
    } else {
        printf("ERROR: Failed to disassemble code\n");
    }
    
    // Clean up
    cs_close(&handle);
    printf("\n===========================\n\n");
}
