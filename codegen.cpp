#include "codegen.h"
#include "library.h"
#include <iostream>
#include <cstring>
#include <iomanip>

using namespace asmjit;

// Resolve NodeType ambiguity by using our AST NodeType explicitly
using ASTNodeType = ::NodeType;

void Codegen::initExternFunctions() {
    // Get addresses of extern C functions for maximum performance
    uint64_t print_addr = reinterpret_cast<uint64_t>(print_int64);
    std::cout << "DEBUG initExternFunctions: storing print_int64 at address 0x" << std::hex << print_addr << std::dec << std::endl;
    extern_function_addresses["print_int64"] = print_addr;
    extern_function_addresses["print_string"] = reinterpret_cast<uint64_t>(print_string);
}

size_t Codegen::allocateScope(LexicalScopeNode* scope, bool is_global) {
    size_t start_pos = buffer.size();
    
    // Save R15 (current lexical scope pointer) on stack
    a.push(x86::r15);
    
    // Get current brk (program break) - this will be our allocated memory
    a.mov(x86::rax, 12);                  // sys_brk (12)
    a.xor_(x86::rdi, x86::rdi);           // xor rdi, rdi (0)
    a.syscall();
    
    // Save current brk in RBX
    a.mov(x86::rbx, x86::rax);
    
    // Set new brk to current + scope size
    a.mov(x86::rax, 12);                  // sys_brk
    a.mov(x86::rcx, x86::rbx);
    a.add(x86::rcx, static_cast<uint32_t>(scope->totalSize));
    a.mov(x86::r10, x86::rcx);            // use R10 instead of RDI
    a.mov(x86::rdi, x86::r10);            // move to RDI only for syscall
    a.syscall();
    a.mov(x86::rcx, x86::r10);            // restore rcx from r10 for later use
    
    // Use the old brk value as our allocated memory
    a.mov(x86::rax, x86::rbx);
    
    // Move allocated memory address to R15 (our lexical scope pointer)
    a.mov(x86::r15, x86::rax);
    
    return buffer.size() - start_pos;
}

size_t Codegen::restoreScope() {
    // Restore previous R15 value from stack
    a.pop(x86::r15);
    return 2; // pop r15 is 2 bytes
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
        case ASTNodeType::VAR_DECL: {
            VarDeclNode* varDecl = static_cast<VarDeclNode*>(node);
            total_length += generateVarDecl(varDecl, current_scope);
            break;
        }
        case ASTNodeType::LITERAL: {
            LiteralNode* literal = static_cast<LiteralNode*>(node);
            total_length += generateLiteral(literal);
            break;
        }
        case ASTNodeType::IDENTIFIER: {
            IdentifierNode* identifier = static_cast<IdentifierNode*>(node);
            
            // Check if this identifier refers to a closure (function)
            if (identifier->varRef && identifier->varRef->type == DataType::CLOSURE) {
                // Treat this as a function call
                FunctionCallNode dummy_call(identifier->value);
                dummy_call.type = ASTNodeType::FUNCTION_CALL;
                // Copy varRef for function resolution
                dummy_call.varRef = identifier->varRef;
                total_length += generateClosureCall(&dummy_call, current_scope);
            } else {
                total_length += generateIdentifier(identifier);
            }
            break;
        }
        case ASTNodeType::PRINT_STMT: {
            total_length += generatePrintStatement(node, current_scope);
            break;
        }
        case ASTNodeType::FUNCTION_DECL: {
            FunctionDeclNode* funcDecl = static_cast<FunctionDeclNode*>(node);
            
            printf("DEBUG: === STARTING code generation for function '%s' at depth=%d ===\n", 
                   funcDecl->funcName.c_str(), funcDecl->depth);
            
            // Bind the label for this function if it exists
            auto labelIt = function_labels.find(funcDecl);
            if (labelIt != function_labels.end()) {
                a.bind(labelIt->second);
                printf("DEBUG: Bound label for function '%s'\n", funcDecl->funcName.c_str());
            }
            
            // Set the function address to current position in buffer (for legacy compatibility)
            funcDecl->functionAddress = a.offset();
            printf("DEBUG: Function '%s' assigned address offset 0x%lx\n", funcDecl->funcName.c_str(), funcDecl->functionAddress);
            
            printf("DEBUG: === STARTING function prologue for '%s' ===\n", funcDecl->funcName.c_str());
            printf("DEBUG: Function has %zu regular params and %zu hidden params\n", 
                   funcDecl->params.size(), funcDecl->hiddenParamsInfo.size());
            
            // NEW STANDARD ABI CALLING CONVENTION PROLOGUE:
            // 1. Standard function prologue
            a.push(x86::rbp);         // push rbp
            a.mov(x86::rbp, x86::rsp); // mov rbp, rsp
            
            // 2. First, save all parameter registers to the stack before we allocate scope
            // This prevents them from being corrupted during heap allocation
            printf("DEBUG: Saving parameter registers before heap allocation\n");
            a.push(x86::rdi);  // push rdi
            a.push(x86::rsi);  // push rsi  
            a.push(x86::rdx);  // push rdx
            a.push(x86::rcx);  // push rcx
            a.push(x86::r8);   // push r8
            a.push(x86::r9);   // push r9
            
            // 3. Allocate lexical scope for this function (now safe to use registers)
            printf("DEBUG: Allocating heap memory for function scope (size=%d)\n", funcDecl->totalSize);
            a.mov(x86::rax, 12);        // sys_brk (12)
            a.xor_(x86::rdi, x86::rdi); // xor rdi, rdi (0)
            a.syscall();
            
            // Save current brk in RBX (non-parameter register)
            a.mov(x86::rbx, x86::rax);  // mov rbx, rax
            
            // Set new brk to current + scope size
            a.mov(x86::rax, 12);        // sys_brk
            a.mov(x86::rdx, x86::rbx);  // mov rdx, rbx  
            a.add(x86::rdx, static_cast<uint32_t>(funcDecl->totalSize)); // add rdx, imm32
            a.mov(x86::rdi, x86::rdx);  // mov rdi, rdx
            a.syscall();
            
            // Set R15 to allocated scope (old brk value in RBX)
            a.mov(x86::r15, x86::rbx);  // mov r15, rbx
            
            // 4. Now restore parameter registers from stack and copy to lexical scope
            // Restore in reverse order
            a.pop(x86::r9);    // pop r9
            a.pop(x86::r8);    // pop r8
            a.pop(x86::rcx);   // pop rcx
            a.pop(x86::rdx);   // pop rdx
            a.pop(x86::rsi);   // pop rsi
            a.pop(x86::rdi);   // pop rdi
            
            // 3. Copy parameters from standard calling convention to lexical scope
            // Standard x86-64 calling convention registers: RDI, RSI, RDX, RCX, R8, R9
            
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
                            a.mov(x86::qword_ptr(x86::r15, paramOffset), x86::rdi);
                            break;
                        case 1: // RSI  
                            printf("DEBUG: Copying from RSI to R15+%d\n", paramOffset);
                            a.mov(x86::qword_ptr(x86::r15, paramOffset), x86::rsi);
                            break;
                        case 2: // RDX
                            a.mov(x86::qword_ptr(x86::r15, paramOffset), x86::rdx);
                            break;
                        case 3: // RCX
                            a.mov(x86::qword_ptr(x86::r15, paramOffset), x86::rcx);
                            break;
                        case 4: // R8
                            a.mov(x86::qword_ptr(x86::r15, paramOffset), x86::r8);
                            break;
                        case 5: // R9
                            a.mov(x86::qword_ptr(x86::r15, paramOffset), x86::r9);
                            break;
                    }
                } else {
                    // Parameter came on stack - load from stack and store to lexical scope
                    size_t stack_offset = 16 + ((i - 6) * 8); // Skip saved rbp + return addr
                    a.mov(x86::rax, x86::qword_ptr(x86::rbp, stack_offset));
                    a.mov(x86::qword_ptr(x86::r15, paramOffset), x86::rax);
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
                            a.mov(x86::qword_ptr(x86::r15, scopeOffset), x86::rdi);
                            break;
                        case 1: // RSI  
                            a.mov(x86::qword_ptr(x86::r15, scopeOffset), x86::rsi);
                            break;
                        case 2: // RDX
                            a.mov(x86::qword_ptr(x86::r15, scopeOffset), x86::rdx);
                            break;
                        case 3: // RCX
                            a.mov(x86::qword_ptr(x86::r15, scopeOffset), x86::rcx);
                            break;
                        case 4: // R8
                            a.mov(x86::qword_ptr(x86::r15, scopeOffset), x86::r8);
                            break;
                        case 5: // R9
                            a.mov(x86::qword_ptr(x86::r15, scopeOffset), x86::r9);
                            break;
                    }
                } else {
                    // Scope address came on stack
                    size_t stack_offset = 16 + ((param_index - 6) * 8);
                    a.mov(x86::rax, x86::qword_ptr(x86::rbp, stack_offset));
                    a.mov(x86::qword_ptr(x86::r15, scopeOffset), x86::rax);
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
            a.mov(x86::rsp, x86::rbp);  // mov rsp, rbp
            a.pop(x86::rbp);            // pop rbp
            a.ret();                    // ret
            
            break;
        }
        case ASTNodeType::FUNCTION_CALL: {
            FunctionCallNode* funcCall = static_cast<FunctionCallNode*>(node);
            total_length += generateClosureCall(funcCall, current_scope);
            break;
        }
        case ASTNodeType::GO_STMT:
            // TODO: Implement these later
            break;
        default:
            printf("DEBUG: Unhandled node type: %d\n", (int)node->type);
            
            // Special handling for identifiers that might be function calls
            if (node->type == ASTNodeType::IDENTIFIER) {
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
                    dummy_call.type = ASTNodeType::FUNCTION_CALL;
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
    size_t start_pos = buffer.size();
    
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
        generateNode(varDecl->children[0].get(), current_scope);
        
        // Store the value (currently in RAX) to R15 + offset
        if (varInfo.type == DataType::INT32) {
            a.mov(x86::dword_ptr(x86::r15, varInfo.offset), x86::eax);
        } else if (varInfo.type == DataType::INT64) {
            a.mov(x86::qword_ptr(x86::r15, varInfo.offset), x86::rax);
        }
    }
    
    return buffer.size() - start_pos;
}

size_t Codegen::generateLiteral(LiteralNode* literal) {
    size_t start_pos = buffer.size();
    // Convert literal value to integer and load into RAX
    int64_t value = std::stoll(literal->value);
    printf("DEBUG generateLiteral: Loading literal value %ld into RAX\n", value);
    a.mov(x86::rax, value);
    return buffer.size() - start_pos;
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
                    a.mov(x86::rdi, x86::rax);
                    break;
                case 1: // RSI
                    printf("DEBUG: Moving parameter %zu from RAX to RSI\n", i);
                    a.mov(x86::rsi, x86::rax);
                    break;
                case 2: // RDX
                    printf("DEBUG: Moving parameter %zu from RAX to RDX\n", i);
                    a.mov(x86::rdx, x86::rax);
                    break;
                case 3: // RCX
                    printf("DEBUG: Moving parameter %zu from RAX to RCX\n", i);
                    a.mov(x86::rcx, x86::rax);
                    break;
                case 4: // R8
                    printf("DEBUG: Moving parameter %zu from RAX to R8\n", i);
                    a.mov(x86::r8, x86::rax);
                    break;
                case 5: // R9
                    printf("DEBUG: Moving parameter %zu from RAX to R9\n", i);
                    a.mov(x86::r9, x86::rax);
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
               i, scope_offset_in_closure, static_cast<size_t>(variable_offset), total_offset);
        
        // Load scope address into RAX
        a.mov(x86::rax, x86::qword_ptr(x86::r10, static_cast<int32_t>(total_offset)));
        
        if (param_index < 6) { // First 6 total parameters go in registers
            switch(param_index) {
                case 0: // RDI
                    printf("DEBUG: Moving hidden param %zu from RAX to RDI\n", i);
                    a.mov(x86::rdi, x86::rax);
                    break;
                case 1: // RSI
                    printf("DEBUG: Moving hidden param %zu from RAX to RSI\n", i);
                    a.mov(x86::rsi, x86::rax);
                    break;
                case 2: // RDX
                    printf("DEBUG: Moving hidden param %zu from RAX to RDX\n", i);
                    a.mov(x86::rdx, x86::rax);
                    break;
                case 3: // RCX
                    printf("DEBUG: Moving hidden param %zu from RAX to RCX\n", i);
                    a.mov(x86::rcx, x86::rax);
                    break;
                case 4: // R8
                    printf("DEBUG: Moving hidden param %zu from RAX to R8\n", i);
                    a.mov(x86::r8, x86::rax);
                    break;
                case 5: // R9
                    printf("DEBUG: Moving hidden param %zu from RAX to R9\n", i);
                    a.mov(x86::r9, x86::rax);
                    break;
            }
        } else {
            // Push onto stack (will be handled below)
            printf("DEBUG: Hidden parameter %zu will go on stack\n", i);
            // We'll need to save this for stack pushing - for now, push immediately
            a.push(x86::rax);
        }
    }
    
    // TODO: Handle stack parameters (for functions with more than 6 total parameters)
    // For now, we'll assume all functions have <= 6 parameters
    
    // Load function address from closure and call
    // Use the closure address already loaded in R10
    a.mov(x86::rax, x86::qword_ptr(x86::r10, static_cast<int32_t>(variable_offset))); // Function address at closure base
    
    printf("DEBUG: About to call function\n");
    // Call the function 
    a.call(x86::rax);
    
    // TODO: Clean up stack if we used it (not needed for <= 6 params)
    
    return buffer.size() - total_length;
}

size_t Codegen::generatePrintStatement(ASTNode* node, LexicalScopeNode* current_scope) {
    size_t total_length = 0;
    
    // For each argument to print, generate code to load it into RDI and call print_int64
    for (auto& child : node->children) {
        // Generate code to load the value into RAX
        total_length += generateNode(child.get(), current_scope);
        
        // Move RAX to RDI (first argument register)
        a.mov(x86::rdi, x86::rax);
        
        // NOTE: Stack alignment removed - caller should ensure proper alignment
        // The stack alignment was corrupting the return address in functions
        
        // Call print_int64 function
        uint64_t print_addr = extern_function_addresses["print_int64"];
        std::cout << "DEBUG generatePrintStatement: retrieved print_int64 address 0x" << std::hex << print_addr << std::dec << std::endl;
        
        // Use AsmJit to call absolute address
        a.mov(x86::rax, print_addr);
        a.call(x86::rax);
    }
    
    return buffer.size() - total_length;
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
            // Create or get a label for this function
            asmjit::Label funcLabel;
            auto labelIt = function_labels.find(funcNode);
            if (labelIt != function_labels.end()) {
                funcLabel = labelIt->second;
            } else {
                funcLabel = a.newLabel();
                function_labels[funcNode] = funcLabel;
            }
            
            // Use AsmJit's proper label system - this will automatically be resolved
            a.lea(x86::rax, x86::ptr(funcLabel));
            
            // Store function address at R15 + varInfo.offset
            a.mov(x86::qword_ptr(x86::r15, varInfo.offset), x86::rax);
            
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
                        a.mov(x86::rax, x86::r15);
                    } else {
                        // During closure creation, we need to get the scope from the current context
                        // The parameter mapping tells us where the target function will expect the scope,
                        // but we need to get it from where it currently is
                        
                        if (neededDepth == scope->depth) {
                            // If the needed scope is the current scope, use R15
                            printf("DEBUG: Storing current scope (R15) for depth %d\n", neededDepth);
                            a.mov(x86::rax, x86::r15);
                        } else {
                            // For parent scopes, we need to load from the current function's parameters
                            // Find the current function scope with cycle detection
                            printf("DEBUG createClosures: Looking for parent function scope from depth %d\n", scope->depth);
                            LexicalScopeNode* currentFunc = scope;
                            std::set<LexicalScopeNode*> visited;
                            int traversal_count = 0;
                            printf("DEBUG createClosures: Starting scope traversal from depth %d to find parent function\n", scope->depth);
                            
                            while (currentFunc && currentFunc->type != ASTNodeType::FUNCTION_DECL) {
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
                            
                            if (currentFunc && currentFunc->type == ASTNodeType::FUNCTION_DECL) {
                                // Get the parameter index for this scope in the current function's context
                                auto it = currentFunc->scopeDepthToParentParameterIndexMap.find(neededDepth);
                                if (it != currentFunc->scopeDepthToParentParameterIndexMap.end()) {
                                    int currentFuncParamIndex = it->second;
                                    if (currentFuncParamIndex == -1) {
                                        printf("DEBUG: Storing current scope (R15) for depth %d via param index -1\n", neededDepth);
                                        a.mov(x86::rax, x86::r15);
                                    } else {
                                        int param_offset = currentFunc->getParameterOffset(currentFuncParamIndex);
                                        printf("DEBUG: Loading scope for depth %d from param offset %d\n", neededDepth, param_offset);
                                        a.mov(x86::rax, x86::qword_ptr(x86::r15, param_offset));
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
                a.mov(x86::qword_ptr(x86::r15, scope_offset), x86::rax);
            }
        }
    }
    
    return total_length;
}

void Codegen::generateProgram(ASTNode& root) {
    buffer.clear();
    function_labels.clear();
    code.init(rt.environment());
    a.~Assembler();  // Destroy the existing assembler
    new (&a) asmjit::x86::Assembler(&code);  // Construct new assembler in place
    
    initExternFunctions();
    
    // Cast root to LexicalScopeNode (global scope)
    LexicalScopeNode* global_scope = static_cast<LexicalScopeNode*>(&root);
    
    // Setup global scope WITHOUT pushing R15 (since there's no parent scope)
    // Allocate memory for global scope
    a.mov(x86::rax, 12);       // sys_brk (12)
    a.xor_(x86::rdi, x86::rdi); // xor rdi, rdi (0)
    a.syscall();
    
    // Save current brk in RBX
    a.mov(x86::rbx, x86::rax); // mov rbx, rax
    
    // Set new brk to current + scope size
    a.mov(x86::rax, 12);       // sys_brk
    a.mov(x86::rcx, x86::rbx);  // mov rcx, rbx  
    a.add(x86::rcx, static_cast<uint32_t>(global_scope->totalSize));
    a.mov(x86::r10, x86::rcx); // mov r10, rcx (use R10 instead of RDI)
    a.mov(x86::rdi, x86::r10); // mov rdi, r10 (move to RDI only for syscall)
    a.syscall();
    a.mov(x86::rcx, x86::r10); // mov rcx, r10 (restore rcx from r10 for later use)
    
    // Use the old brk value as our allocated memory
    a.mov(x86::rax, x86::rbx); // mov rax, rbx
    
    // Move allocated memory address to R15 (our lexical scope pointer)
    a.mov(x86::r15, x86::rax);
    
    // Create closures for global scope
    createClosures(global_scope);
    
    // FIRST PASS: Generate main program flow (skip function definitions)
    // Main program code (skip function definitions)
    for (auto& child : global_scope->ASTNode::children) {
        if (child->type != ASTNodeType::FUNCTION_DECL) {
            generateNode(child.get(), global_scope);
        }
    }
    
    // Create a label for jumping over function definitions
    asmjit::Label after_functions = a.newLabel();
    a.jmp(after_functions);
    
    // SECOND PASS: Generate function definitions
    for (auto& child : global_scope->ASTNode::children) {
        if (child->type == ASTNodeType::FUNCTION_DECL) {
            generateNode(child.get(), global_scope);
        }
    }
    
    // Bind the label after functions
    a.bind(after_functions);
    
    // Exit cleanly
    a.mov(x86::rax, 60);  // sys_exit
    a.xor_(x86::rdi, x86::rdi);      // exit code 0
    a.syscall();
    
    // Finalize the code
    a.finalize();
    
    // Get the machine code from AsmJit
    buffer.resize(code.codeSize());
    code.relocateToBase(0); // Relocate to base address 0 for now
    code.copyFlattenedData(buffer.data(), buffer.size());
}

void Codegen::writeProgramToExecutable() {
    // Allocate executable memory
    void* exec_mem = mmap(nullptr, buffer.size(), 
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (exec_mem == MAP_FAILED) {
        std::cerr << "Failed to allocate executable memory" << std::endl;
        return;
    }

    // Convert relative addresses to absolute addresses in executable memory
    uint64_t base_address = reinterpret_cast<uint64_t>(exec_mem);
    
    // Copy machine code to executable memory
    std::memcpy(exec_mem, buffer.data(), buffer.size());
    
    // Disassemble the code
    disassembleCode(buffer, base_address);
    
    // Execute the code
    typedef void (*func_ptr)();
    func_ptr func = reinterpret_cast<func_ptr>(exec_mem);
    func();
    
    // Clean up
    munmap(exec_mem, buffer.size());
}

size_t Codegen::loadVariableIntoRegister(IdentifierNode* identifier, Register target_reg) {
    size_t total_length = 0;
    
    // Ensure accessedIn is properly set during analysis
    if (!identifier->accessedIn) {
        throw std::runtime_error("Variable access scope not set during analysis: " + identifier->value);
    }
    
    auto access = identifier->getVariableAccess();
    
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
        
        // Get the target register
        x86::Gp targetReg;
        switch(target_reg) {
            case Register::RAX: targetReg = x86::rax; break;
            case Register::RCX: targetReg = x86::rcx; break;
            case Register::RDX: targetReg = x86::rdx; break;
            case Register::RBX: targetReg = x86::rbx; break;
            case Register::RSP: targetReg = x86::rsp; break;
            case Register::RBP: targetReg = x86::rbp; break;
            case Register::RSI: targetReg = x86::rsi; break;
            case Register::RDI: targetReg = x86::rdi; break;
            case Register::R8:  targetReg = x86::r8; break;
            case Register::R9:  targetReg = x86::r9; break;
            case Register::R10: targetReg = x86::r10; break;
            case Register::R11: targetReg = x86::r11; break;
            case Register::R12: targetReg = x86::r12; break;
            case Register::R13: targetReg = x86::r13; break;
            case Register::R14: targetReg = x86::r14; break;
            case Register::R15: targetReg = x86::r15; break;
        }
        
        a.mov(targetReg, x86::qword_ptr(x86::r15, access.offset));
    } else {
        // Variable is in a parent scope - load scope address from hidden parameter
        printf("DEBUG: Loading from parent scope via parameter offset %d + variable offset %d\n", access.parameterOffset, access.offset);
        
        // Use the pre-calculated parameter offset directly (accounts for variable-sized parameters)
        printf("DEBUG: Using parameter offset: %d\n", access.parameterOffset);
        
        // Get the target register
        x86::Gp targetReg;
        switch(target_reg) {
            case Register::RAX: targetReg = x86::rax; break;
            case Register::RCX: targetReg = x86::rcx; break;
            case Register::RDX: targetReg = x86::rdx; break;
            case Register::RBX: targetReg = x86::rbx; break;
            case Register::RSP: targetReg = x86::rsp; break;
            case Register::RBP: targetReg = x86::rbp; break;
            case Register::RSI: targetReg = x86::rsi; break;
            case Register::RDI: targetReg = x86::rdi; break;
            case Register::R8:  targetReg = x86::r8; break;
            case Register::R9:  targetReg = x86::r9; break;
            case Register::R10: targetReg = x86::r10; break;
            case Register::R11: targetReg = x86::r11; break;
            case Register::R12: targetReg = x86::r12; break;
            case Register::R13: targetReg = x86::r13; break;
            case Register::R14: targetReg = x86::r14; break;
            case Register::R15: targetReg = x86::r15; break;
        }
        
        // Load the parent scope address from parameter, then load the variable
        printf("DEBUG: About to load scope address from R15+%d\n", access.parameterOffset);
        a.mov(targetReg, x86::qword_ptr(x86::r15, access.parameterOffset));
        printf("DEBUG: About to load variable from scope+%d\n", access.offset);
        a.mov(targetReg, x86::qword_ptr(targetReg, access.offset));
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
            printf("DEBUG: Target register is NOT R15, moving R15 to target\n");
            // Get the target register
            x86::Gp targetReg;
            switch(target_reg) {
                case Register::RAX: targetReg = x86::rax; break;
                case Register::RCX: targetReg = x86::rcx; break;
                case Register::RDX: targetReg = x86::rdx; break;
                case Register::RBX: targetReg = x86::rbx; break;
                case Register::RSP: targetReg = x86::rsp; break;
                case Register::RBP: targetReg = x86::rbp; break;
                case Register::RSI: targetReg = x86::rsi; break;
                case Register::RDI: targetReg = x86::rdi; break;
                case Register::R8:  targetReg = x86::r8; break;
                case Register::R9:  targetReg = x86::r9; break;
                case Register::R10: targetReg = x86::r10; break;
                case Register::R11: targetReg = x86::r11; break;
                case Register::R12: targetReg = x86::r12; break;
                case Register::R13: targetReg = x86::r13; break;
                case Register::R14: targetReg = x86::r14; break;
                case Register::R15: targetReg = x86::r15; break;
            }
            a.mov(targetReg, x86::r15);
        }
    } else {
        // Variable is in a parent scope - load the parent scope address from hidden parameter
        printf("DEBUG: Loading parent scope address from parameter offset %d\n", access.parameterOffset);
        
        // Use the pre-calculated parameter offset directly (accounts for variable-sized parameters)
        printf("DEBUG: Using parameter offset: %d\n", access.parameterOffset);
        
        // Get the target register
        x86::Gp targetReg;
        switch(target_reg) {
            case Register::RAX: targetReg = x86::rax; break;
            case Register::RCX: targetReg = x86::rcx; break;
            case Register::RDX: targetReg = x86::rdx; break;
            case Register::RBX: targetReg = x86::rbx; break;
            case Register::RSP: targetReg = x86::rsp; break;
            case Register::RBP: targetReg = x86::rbp; break;
            case Register::RSI: targetReg = x86::rsi; break;
            case Register::RDI: targetReg = x86::rdi; break;
            case Register::R8:  targetReg = x86::r8; break;
            case Register::R9:  targetReg = x86::r9; break;
            case Register::R10: targetReg = x86::r10; break;
            case Register::R11: targetReg = x86::r11; break;
            case Register::R12: targetReg = x86::r12; break;
            case Register::R13: targetReg = x86::r13; break;
            case Register::R14: targetReg = x86::r14; break;
            case Register::R15: targetReg = x86::r15; break;
        }
        
        // Load the parent scope address from parameter
        a.mov(targetReg, x86::qword_ptr(x86::r15, access.parameterOffset));
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

void Codegen::runWithUnicornDebugger() {
    std::cout << "UNICORN: Starting Unicorn Engine debugging session" << std::endl;
    
    UnicornDebugger debugger;
    if (!debugger.initialize()) {
        std::cerr << "Failed to initialize Unicorn debugger: " << debugger.getLastError() << std::endl;
        return;
    }
    
    // Allocate memory regions
    uint64_t code_base = 0x400000;  // Code at 4MB
    uint64_t heap_base = 0x800000;  // Heap at 8MB  
    uint64_t heap_size = 0x100000;  // 1MB heap
    uint64_t stack_base = 0x700000; // Stack at 7MB
    uint64_t stack_size = 0x10000;  // 64KB stack
    
    // Set up memory layout
    if (!debugger.setupMemory(heap_base, heap_size, stack_base, stack_size)) {
        std::cerr << "Failed to setup memory: " << debugger.getLastError() << std::endl;
        return;
    }
    
    // Load code into emulator (AsmJit has already resolved all labels)
    if (!debugger.loadCode(buffer.data(), buffer.size(), code_base)) {
        std::cerr << "Failed to load code: " << debugger.getLastError() << std::endl;
        return;
    }
    
    // Register external function handlers
    uint64_t print_int64_addr = reinterpret_cast<uint64_t>(print_int64);
    debugger.registerExternalFunction(print_int64_addr, "print_int64");
    
    // Disassemble the code for reference
    disassembleCode(buffer, code_base);
    
    // Run the program
    std::cout << "UNICORN: Starting execution..." << std::endl;
    if (!debugger.run(code_base)) {
        std::cerr << "UNICORN: Execution failed: " << debugger.getLastError() << std::endl;
        
        // Show where we failed
        uint64_t pc = debugger.getRegister(UC_X86_REG_RIP);
        std::cout << "UNICORN: Program counter at failure: 0x" << std::hex << pc << std::dec << std::endl;
        
        // Dump memory around the problematic address if it's a memory access issue
        debugger.dumpMemory(pc - 16, 32);
        
        return;
    }
    
    std::cout << "UNICORN: Execution completed successfully!" << std::endl;
}
