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
    total_length += emitter.emitPushR15();
    
    // For debugging: use a simple approach - allocate using brk syscall or just use a hardcoded address
    // Let's allocate memory using the brk syscall instead
    // First get current brk
    total_length += emitter.emitMovRAXImm64(12);       // sys_brk
    total_length += emitter.emitXorRdiRdi();           // addr = 0 (get current brk)
    total_length += emitter.emitSyscall();
    
    // Save current brk in RBX
    total_length += emitter.emitBytes({0x48, 0x89, 0xC3}); // mov rbx, rax
    
    // Set new brk to current + scope size
    total_length += emitter.emitMovRAXImm64(12);       // sys_brk
    total_length += emitter.emitBytes({0x48, 0x89, 0xDF}); // mov rdi, rbx
    total_length += emitter.emitBytes({0x48, 0x81, 0xC7}); // add rdi, imm32
    total_length += emitter.emitU32(static_cast<uint32_t>(scope->totalSize));
    total_length += emitter.emitSyscall();
    
    // Use the old brk value as our allocated memory
    total_length += emitter.emitBytes({0x48, 0x89, 0xD8}); // mov rax, rbx
    
    // Move allocated memory address to R15 (our lexical scope pointer)
    total_length += emitter.emitMovR15RAX();
    
    // Debug: Check if mmap succeeded by comparing RAX to -1
    // This is just for debugging - we'll print the result
    // mov rdi, rax; mov rax, 1; mov rsi, 1; mov rdx, 8; syscall (write to stdout)
    // But for now, let's just continue...
    
    return total_length;
}

size_t Codegen::restoreScope() {
    // Restore previous R15 value from stack
    return emitter.emitPopR15();
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
            
            // Function prologue - establish new stack frame
            // Push base pointer and set up new frame
            total_length += emitter.emitBytes({0x55}); // push rbp
            total_length += emitter.emitBytes({0x48, 0x89, 0xE5}); // mov rbp, rsp
            
            // Handle function parameters - move from System V ABI registers to function scope variables
            for (size_t i = 0; i < funcDecl->params.size() && i < 6; i++) {
                const std::string& paramName = funcDecl->params[i];
                
                // Find the parameter variable in the function scope
                auto it = funcDecl->variables.find(paramName);
                if (it != funcDecl->variables.end()) {
                    VariableInfo& paramVar = it->second;
                    
                    // Move parameter from register to RAX, then to variable location
                    total_length += emitter.emitMovRAXFromParam(static_cast<int>(i));
                    
                    // Store RAX to R15 + offset (parameter variable location)
                    if (paramVar.type == DataType::INT64) {
                        total_length += emitter.emitMovQwordPtrR15PlusOffsetRAX(paramVar.offset);
                    } else if (paramVar.type == DataType::INT32) {
                        total_length += emitter.emitMovDwordPtrR15PlusOffsetEAX(paramVar.offset);
                    }
                }
            }
            
            // Generate function body (children of this node)
            for (auto& child : funcDecl->ASTNode::children) {
                total_length += generateNode(child.get(), funcDecl);
            }
            
            // Add some debug output before returning
            // Generate a function that writes a specific value to R15+8 
            // mov qword ptr [r15+8], 0x12345678
            total_length += emitter.emitBytes({0x49, 0xC7, 0x47, 0x08}); // mov qword ptr [r15+8], imm32
            total_length += emitter.emitU32(0x12345678); // immediate value
            
            // Function epilogue - restore stack frame and return
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
    
    // System V ABI: Parameter registers are RDI, RSI, RDX, RCX, R8, R9 (0-5)
    // Parameters beyond 6 go on the stack (not implemented yet)
    
    // First, generate code for each argument and move to appropriate parameter register
    for (size_t i = 0; i < funcCall->args.size() && i < 6; i++) {
        // Generate code to evaluate the argument (result in RAX)
        total_length += generateNode(funcCall->args[i].get(), current_scope);
        
        // Move RAX to the appropriate parameter register
        total_length += emitter.emitMovParamFromRAX(static_cast<int>(i));
    }
    
    // TODO: Handle arguments beyond 6 by pushing to stack
    if (funcCall->args.size() > 6) {
        std::cerr << "Warning: Function calls with more than 6 arguments not yet supported" << std::endl;
    }

    // Get the function address directly (this loads function address into RAX)
    total_length += loadVariableIntoRegister(static_cast<IdentifierNode*>(funcCall), current_scope, Register::RAX);

    // Call the function - this pushes return address and jumps
    total_length += emitter.emitBytes({0xFF, 0xD0}); // call rax

    return total_length;
}size_t Codegen::generatePrintStatement(ASTNode* node, LexicalScopeNode* current_scope) {
    size_t total_length = 0;
    
    // For each argument to print, generate code to load it into RDI and call print_int64
    for (auto& child : node->children) {
        // Generate code to load the value into RAX
        total_length += generateNode(child.get(), current_scope);
        
        // Move RAX to RDI (first argument register)
        total_length += emitter.emitBytes({0x48, 0x89, 0xC7}); // mov rdi, rax
        
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
            // This is a closure variable - need to create the closure structure
            FunctionDeclNode* funcNode = varInfo.funcNode;
            if (!funcNode) continue;
            
            // Closure structure: [function_address][scope_addr_1][scope_addr_2]...
            // First, load the function address into RAX using placeholder
            
            // mov rax, <placeholder>
            total_length += emitter.emitBytes({0x48, 0xB8}); // mov rax, imm64 prefix
            
            // Create patch entry with exact offset
            size_t patch_offset;
            total_length += emitter.emitFunctionAddressPlaceholder(patch_offset);
            function_patches.push_back(FunctionPatch(patch_offset, funcNode));
            
            // Store function address at R15 + offset
            total_length += emitter.emitMovQwordPtrR15PlusOffsetRAX(varInfo.offset);
            
            // Now store addresses of needed parent scopes
            // For each scope in funcNode->allNeeded, we need to store its address
            for (size_t i = 0; i < funcNode->allNeeded.size(); i++) {
                int neededDepth = funcNode->allNeeded[i];
                
                // Get parameter index for this scope depth
                auto it = funcNode->scopeDepthToParentParameterIndexMap.find(neededDepth);
                if (it != funcNode->scopeDepthToParentParameterIndexMap.end()) {
                    int paramIndex = it->second;
                    
                    if (paramIndex == -1) {
                        // This scope is in R15 (current scope)
                        // mov rax, r15
                        total_length += emitter.emitBytes({0x4C, 0x89, 0xF8}); // mov rax, r15
                    } else {
                        // Load from parameter using System V ABI
                        total_length += emitter.emitMovRAXFromParam(paramIndex);
                    }
                } else {
                    // Scope not found in parameter map - this is an error
                    throw std::runtime_error("Scope dependency not found: function '" + 
                                           funcNode->funcName + "' needs scope at depth " + 
                                           std::to_string(neededDepth) + " but no parameter mapping exists");
                }
                
                // Store the scope address at closure offset
                total_length += emitter.emitMovQwordPtrR15PlusOffsetRAX(varInfo.offset + 8 + (i * 8));
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
    
    // Allocate memory for global scope
    allocateScope(global_scope, true);
    
    // FIRST PASS: Generate main program flow (skip function definitions)
    // First, create closures (this generates code that must run)
    createClosures(global_scope);
    
    // Then generate other main program code (skip function definitions)
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
    // Restore previous lexical scope (pop R15)
    restoreScope();
    
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
    
    // Update function addresses to absolute addresses
    for (const auto& patch : function_patches) {
        if (!patch.is_string_patch && patch.func) {
            patch.func->functionAddress = base_address + patch.func->functionAddress;
        }
    }
    
    // Patch all addresses (both function and string addresses) BEFORE copying to executable memory
    for (const auto& patch : function_patches) {
        uint64_t addr_to_patch;
        
        if (patch.is_string_patch) {
            // For string patches, calculate absolute address
            addr_to_patch = base_address + patch.string_offset;
        } else {
            // For function patches, use the updated absolute function address
            if (patch.func == nullptr) {
                throw std::runtime_error("ERROR: Function patch has null function pointer at offset " + std::to_string(patch.offset_in_buffer));
            }
            addr_to_patch = patch.func->functionAddress;
        }
        
        // Write the address into the buffer at the exact offset
        for (int i = 0; i < 8; i++) {
            emitter.buffer[patch.offset_in_buffer + i] = static_cast<uint8_t>((addr_to_patch >> (i * 8)) & 0xFF);
        }
    }

    // Copy machine code to executable memory AFTER patching
    std::memcpy(exec_mem, emitter.buffer.data(), emitter.buffer.size());
    
    
    // Execute the code
    typedef void (*func_ptr)();
    func_ptr func = reinterpret_cast<func_ptr>(exec_mem);
    func();
    
    // Clean up
    munmap(exec_mem, emitter.buffer.size());
}

size_t Codegen::loadVariableIntoRegister(IdentifierNode* identifier, LexicalScopeNode* current_scope, Register target_reg) {
    size_t total_length = 0;
    auto access = identifier->getVariableAccess(current_scope);
    int reg_num = static_cast<int>(target_reg);
    
    // Check if variable is defined in the current scope
    if (identifier->varRef->definedIn == current_scope) {
        // Variable is in current scope - access via R15 + offset
        total_length += emitter.emitMovRegFromMemory(reg_num, 15, access.offset); // R15 = 15
    } else {
        // Variable is in a parent scope - need to load scope address from parameter
        // Get the depth of the scope where the variable is defined
        int definedDepth = identifier->varRef->definedIn->depth;
        
        // Find this depth's index in the current function's allNeeded array
        FunctionDeclNode* currentFunc = static_cast<FunctionDeclNode*>(current_scope);
        int neededIndex = -1;
        for (size_t i = 0; i < currentFunc->allNeeded.size(); i++) {
            if (currentFunc->allNeeded[i] == definedDepth) {
                neededIndex = static_cast<int>(i);
                break;
            }
        }
        
        if (neededIndex == -1) {
            throw std::runtime_error("Variable '" + identifier->value + "' defined at depth " + 
                                   std::to_string(definedDepth) + " not found in current function's allNeeded array");
        }
        
        // Calculate actual parameter index: regular params + scope param index
        int paramIndex = static_cast<int>(currentFunc->params.size()) + neededIndex;
        
        // First, load the parent scope address from the appropriate parameter register into target register
        total_length += emitter.emitMovRegFromParam(reg_num, paramIndex);
        
        // Now load the variable from [target_reg + offset]
        total_length += emitter.emitMovRegFromMemory(reg_num, reg_num, access.offset);
    }
    
    return total_length;
}
