#include "codegen.h"
#include <iostream>
#include <cstring>

void Codegen::initExternFunctions() {
    // Get addresses of extern C functions for maximum performance
    extern_function_addresses["print_int64"] = reinterpret_cast<uint64_t>(print_int64);
}

size_t Codegen::allocateScope(LexicalScopeNode* scope, bool is_global) {
    size_t total_length = 0;
    
    // Save R15 (current lexical scope pointer) on stack
    total_length += emitter.emitPushR15();
    
    // Allocate memory for this scope using mmap syscall
    // mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
    total_length += emitter.emitMovRAXImm64(9);        // sys_mmap
    total_length += emitter.emitXorRdiRdi();           // addr = NULL (let kernel choose)
    total_length += emitter.emitMovRSIImm64(scope->totalSize); // length = scope size
    total_length += emitter.emitMovRDXImm64(3);        // prot = PROT_READ | PROT_WRITE
    total_length += emitter.emitMovRCXImm64(0x22);     // flags = MAP_PRIVATE | MAP_ANONYMOUS
    total_length += emitter.emitMovR8Imm64(-1);        // fd = -1
    total_length += emitter.emitMovR9Imm64(0);         // offset = 0
    total_length += emitter.emitSyscall();
    
    // Move allocated memory address to R15 (our lexical scope pointer)
    total_length += emitter.emitMovR15RAX();
    
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
            total_length += generateIdentifier(identifier, current_scope);
            break;
        }
        case NodeType::PRINT_STMT: {
            total_length += generatePrintStatement(node, current_scope);
            break;
        }
        case NodeType::FUNCTION_DECL: {
            // Set the function address to current position in buffer
            FunctionDeclNode* funcDecl = static_cast<FunctionDeclNode*>(node);
            funcDecl->functionAddress = emitter.buffer.size();
            
            // TODO: Generate function body later
            // For now, just skip function generation
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
    size_t total_length = 0;
    
    // Get variable access info
    auto access = identifier->getVariableAccess(current_scope);
    
    // Check if variable is defined in the current scope
    if (identifier->varRef->definedIn == current_scope) {
        // Variable is in current scope - access via R15 + offset
        if (identifier->varRef && identifier->varRef->type == DataType::INT32) {
            // mov eax, [r15+offset] - need to add this instruction
            // For now, load as 64-bit
            if (access.offset == 0) {
                total_length += emitter.emitBytes({0x49, 0x8B, 0x07}); // mov rax, [r15]
            } else if (access.offset >= -128 && access.offset <= 127) {
                total_length += emitter.emitBytes({0x49, 0x8B, 0x47, static_cast<uint8_t>(access.offset)}); // mov rax, [r15+offset8]
            } else {
                total_length += emitter.emitBytes({0x49, 0x8B, 0x87}) + emitter.emitU32(static_cast<uint32_t>(access.offset)); // mov rax, [r15+offset32]
            }
        } else {
            // Load 64-bit value
            if (access.offset == 0) {
                total_length += emitter.emitBytes({0x49, 0x8B, 0x07}); // mov rax, [r15]
            } else if (access.offset >= -128 && access.offset <= 127) {
                total_length += emitter.emitBytes({0x49, 0x8B, 0x47, static_cast<uint8_t>(access.offset)}); // mov rax, [r15+offset8]
            } else {
                total_length += emitter.emitBytes({0x49, 0x8B, 0x87}) + emitter.emitU32(static_cast<uint32_t>(access.offset)); // mov rax, [r15+offset32]
            }
        }
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
        
        // First, load the parent scope address from the appropriate parameter register into RAX
        switch (paramIndex) {
            case 0: total_length += emitter.emitBytes({0x48, 0x89, 0xF8}); break; // mov rax, rdi
            case 1: total_length += emitter.emitBytes({0x48, 0x89, 0xF0}); break; // mov rax, rsi  
            case 2: total_length += emitter.emitBytes({0x48, 0x89, 0xD0}); break; // mov rax, rdx
            case 3: total_length += emitter.emitBytes({0x48, 0x89, 0xC8}); break; // mov rax, rcx
            case 4: total_length += emitter.emitBytes({0x4C, 0x89, 0xC0}); break; // mov rax, r8
            case 5: total_length += emitter.emitBytes({0x4C, 0x89, 0xC8}); break; // mov rax, r9
            default:
                throw std::runtime_error("Parameter index " + std::to_string(paramIndex) + 
                                       " not supported - only registers 0-5 implemented");
        }
        
        // Now load the variable from [rax + offset]
        if (access.offset == 0) {
            total_length += emitter.emitBytes({0x48, 0x8B, 0x00}); // mov rax, [rax]
        } else if (access.offset >= -128 && access.offset <= 127) {
            total_length += emitter.emitBytes({0x48, 0x8B, 0x40, static_cast<uint8_t>(access.offset)}); // mov rax, [rax+offset8]
        } else {
            total_length += emitter.emitBytes({0x48, 0x8B, 0x80}) + emitter.emitU32(static_cast<uint32_t>(access.offset)); // mov rax, [rax+offset32]
        }
    }
    
    return total_length;
}

size_t Codegen::generateFunctionCall(FunctionCallNode* funcCall, LexicalScopeNode* current_scope) {
    size_t total_length = 0;
    
    // Get the closure for this function
    auto access = funcCall->getVariableAccess(current_scope);
    
    if (access.parameterIndex == -1) {
        // Function closure is in current scope at R15 + offset
        
        // 1. Load function address from closure into RAX
        // mov rax, [r15 + offset] - get function pointer from closure
        if (access.offset == 0) {
            total_length += emitter.emitBytes({0x49, 0x8B, 0x07}); // mov rax, [r15]
        } else if (access.offset >= -128 && access.offset <= 127) {
            total_length += emitter.emitBytes({0x49, 0x8B, 0x47, static_cast<uint8_t>(access.offset)}); // mov rax, [r15+offset8]
        } else {
            total_length += emitter.emitBytes({0x49, 0x8B, 0x87}) + emitter.emitU32(static_cast<uint32_t>(access.offset)); // mov rax, [r15+offset32]
        }
        
        // 2. Save function address for later call
        total_length += emitter.emitPushRAX(); // push rax (save function address)
        
        // 3. Set up parameters according to System V ABI
        // First, handle explicit arguments from funcCall->args
        for (size_t i = 0; i < funcCall->args.size() && i < 6; i++) {
            // Generate code to load argument into RAX
            total_length += generateNode(funcCall->args[i].get(), current_scope);
            
            // Move RAX to appropriate parameter register
            switch (i) {
                case 0: total_length += emitter.emitBytes({0x48, 0x89, 0xC7}); break; // mov rdi, rax
                case 1: total_length += emitter.emitBytes({0x48, 0x89, 0xC6}); break; // mov rsi, rax
                case 2: total_length += emitter.emitBytes({0x48, 0x89, 0xC2}); break; // mov rdx, rax
                case 3: total_length += emitter.emitBytes({0x48, 0x89, 0xC1}); break; // mov rcx, rax
                case 4: total_length += emitter.emitBytes({0x49, 0x89, 0xC0}); break; // mov r8, rax
                case 5: total_length += emitter.emitBytes({0x49, 0x89, 0xC1}); break; // mov r9, rax
            }
        }
        
        // 4. Now pass scope addresses as hidden parameters
        // Get the function's closure and extract needed scope addresses
        FunctionDeclNode* targetFunc = funcCall->varRef->funcNode;
        if (targetFunc) {
            size_t param_index = funcCall->args.size(); // Start after explicit parameters
            
            for (size_t i = 0; i < targetFunc->allNeeded.size() && param_index < 6; i++, param_index++) {
                // Load scope address from closure structure
                size_t scope_offset = access.offset + 8 + (i * 8); // +8 to skip function pointer
                
                if (scope_offset == 0) {
                    total_length += emitter.emitBytes({0x49, 0x8B, 0x07}); // mov rax, [r15]
                } else if (scope_offset >= -128 && scope_offset <= 127) {
                    total_length += emitter.emitBytes({0x49, 0x8B, 0x47, static_cast<uint8_t>(scope_offset)}); // mov rax, [r15+offset8]
                } else {
                    total_length += emitter.emitBytes({0x49, 0x8B, 0x87}) + emitter.emitU32(static_cast<uint32_t>(scope_offset)); // mov rax, [r15+offset32]
                }
                
                // Move to appropriate parameter register
                switch (param_index) {
                    case 0: total_length += emitter.emitBytes({0x48, 0x89, 0xC7}); break; // mov rdi, rax
                    case 1: total_length += emitter.emitBytes({0x48, 0x89, 0xC6}); break; // mov rsi, rax
                    case 2: total_length += emitter.emitBytes({0x48, 0x89, 0xC2}); break; // mov rdx, rax
                    case 3: total_length += emitter.emitBytes({0x48, 0x89, 0xC1}); break; // mov rcx, rax
                    case 4: total_length += emitter.emitBytes({0x49, 0x89, 0xC0}); break; // mov r8, rax
                    case 5: total_length += emitter.emitBytes({0x49, 0x89, 0xC1}); break; // mov r9, rax
                }
            }
        }
        
        // 5. Call the function
        total_length += emitter.emitPopRAX();  // pop rax (restore function address)
        total_length += emitter.emitBytes({0xFF, 0xD0}); // call rax
        
    } else {
        throw std::runtime_error("Function calls from parent scope parameters not yet implemented");
    }
    
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
            FunctionPatch patch;
            patch.func = funcNode;
            total_length += emitter.emitFunctionAddressPlaceholder(patch.offset_in_buffer);
            function_patches.push_back(patch);
            
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
        uint64_t func_addr = patch.func->functionAddress;
        
        // Write the address into the buffer at the exact offset
        for (int i = 0; i < 8; i++) {
            emitter.buffer[patch.offset_in_buffer + i] = static_cast<uint8_t>((func_addr >> (i * 8)) & 0xFF);
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
    
    // Create closures for functions in global scope
    createClosures(global_scope);
    
    // Walk the AST and generate code for all children (these are unique_ptr<ASTNode>)
    for (auto& child : global_scope->ASTNode::children) {
        generateNode(child.get(), global_scope);
    }
    
    // Restore previous lexical scope (pop R15)
    restoreScope();
    
    // For now, just exit cleanly
    emitter.emitMovRAXImm64(60);  // sys_exit
    emitter.emitXorRdiRdi();      // exit code 0
    emitter.emitSyscall();
}

void Codegen::writeProgramToExecutable() {
    // Allocate executable memory
    void* exec_mem = mmap(nullptr, emitter.buffer.size(), 
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (exec_mem == MAP_FAILED) {
        std::cerr << "Failed to allocate executable memory" << std::endl;
        return;
    }
    
    // Convert relative function addresses to absolute addresses in executable memory
    uint64_t base_address = reinterpret_cast<uint64_t>(exec_mem);
    for (const auto& patch : function_patches) {
        patch.func->functionAddress = base_address + patch.func->functionAddress;
    }
    
    // Patch function addresses with absolute addresses
    patchFunctionAddresses();
    
    // Copy machine code to executable memory
    std::memcpy(exec_mem, emitter.buffer.data(), emitter.buffer.size());
    
    // Execute the code
    typedef void (*func_ptr)();
    func_ptr func = reinterpret_cast<func_ptr>(exec_mem);
    func();
    
    // Clean up
    munmap(exec_mem, emitter.buffer.size());
}
