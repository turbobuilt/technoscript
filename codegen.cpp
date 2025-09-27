#include "codegen.h"
#include <iostream>
#include <cstdlib>
#include <cstring>

// External C functions implementation
extern "C" {
    void* malloc_wrapper(size_t size) {
        return malloc(size);
    }
    
    void free_wrapper(void* ptr) {
        free(ptr);
    }
}

// Codegen class implementation (main interface)
Codegen::Codegen() : generatedFunction(nullptr) {
}

Codegen::~Codegen() {
    // Function cleanup is handled by asmjit runtime
}

void Codegen::generateProgram(ASTNode& root) {
    generatedFunction = generator.generateCode(&root);
}

void Codegen::run() {
    if (!generatedFunction) {
        throw std::runtime_error("No generated function to run");
    }
    
    std::cout << "\n=== Executing Generated Code ===" << std::endl;
    
    // Cast to function pointer and call
    typedef int (*MainFunc)();
    MainFunc func = reinterpret_cast<MainFunc>(generatedFunction);
    int result = func();
    
    std::cout << "=== Execution Complete (returned " << result << ") ===" << std::endl;
}

// CodeGenerator class implementation
CodeGenerator::CodeGenerator() : currentScope(nullptr) {
    // Builder will be initialized in generateCode when code holder is ready
    
    // Initialize Capstone for disassembly
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstoneHandle) != CS_ERR_OK) {
        throw std::runtime_error("Failed to initialize Capstone disassembler");
    }
    cs_option(capstoneHandle, CS_OPT_DETAIL, CS_OPT_ON);
}

CodeGenerator::~CodeGenerator() {
    cs_close(&capstoneHandle);
}

void* CodeGenerator::generateCode(ASTNode* root) {
    // Reset and initialize code holder
    code.reset();
    code.init(rt.environment(), rt.cpuFeatures());
    
    // Create builder with the code holder
    cb = new x86::Builder(&code);
    
    std::cout << "=== Generated Assembly Code ===" << std::endl;
    
    // Generate code for the program
    generateProgram(root);
    
    std::cout << "Code size after program: " << code.codeSize() << std::endl;
    
    // Finalize the code (this resolves all forward references)
    cb->finalize();
    
    std::cout << "Final code size: " << code.codeSize() << std::endl;
    
    // Clean up builder
    delete cb;
    cb = nullptr;
    
    // Commit the code to executable memory
    void* executableFunc;
    Error err = rt.add(&executableFunc, &code);
    if (err) {
        std::cout << "Error details: " << DebugUtils::errorAsString(err) << std::endl;
        std::cout << "Code size: " << code.codeSize() << std::endl;
        throw std::runtime_error("Failed to generate code: " + std::string(DebugUtils::errorAsString(err)));
    }
    
    std::cout << "Successfully generated code, size: " << code.codeSize() << " bytes" << std::endl;
    
    // Get the code size for disassembly
    size_t codeSize = code.codeSize();
    
    // Disassemble and print the generated code
    disassembleAndPrint(executableFunc, codeSize);
    
    return executableFunc;
}

void CodeGenerator::declareExternalFunctions() {
    // We'll resolve these at runtime by getting their addresses
    printInt64Label = cb->newLabel();
    mallocLabel = cb->newLabel();
    freeLabel = cb->newLabel();
}

void CodeGenerator::generateProgram(ASTNode* root) {
    if (!root) {
        throw std::runtime_error("Null program root");
    }
    
    // Root should always be a FUNCTION_DECL (the main function)
    if (root->type == AstNodeType::FUNCTION_DECL) {
        // Treat the main function as the program root
        visitNode(root);
    } else {
        throw std::runtime_error("Invalid program root node type - expected FUNCTION_DECL");
    }
}

void CodeGenerator::visitNode(ASTNode* node) {
    if (!node) return;
    
    switch (node->type) {
        case AstNodeType::LEXICAL_SCOPE:
            generateLexicalScope(static_cast<LexicalScopeNode*>(node));
            break;
        case AstNodeType::VAR_DECL:
            generateVarDecl(static_cast<VarDeclNode*>(node));
            break;
        case AstNodeType::PRINT_STMT:
            generatePrintStmt(node);
            break;
        case AstNodeType::FUNCTION_DECL:
            generateFunctionDecl(static_cast<FunctionDeclNode*>(node));
            break;
        case AstNodeType::FUNCTION_CALL:
            generateFunctionCall(static_cast<FunctionCallNode*>(node));
            break;
        default:
            // For other nodes, just visit children
            for (auto& child : node->children) {
                visitNode(child.get());
            }
            break;
    }
}

void CodeGenerator::allocateScope(LexicalScopeNode* scope) {
    std::cout << "Allocating scope of size: " << scope->totalSize << " bytes" << std::endl;


    // push r14 to stack
    cb->push(x86::r14);
    // copy r15 to r14
    cb->mov(x86::r14, x86::r15);
    
    // Call malloc to allocate scope
    // mov rdi, scope->totalSize (first argument)
    cb->mov(x86::rdi, scope->totalSize);
    
    // Call malloc - we need to call the actual malloc function
    // For simplicity, we'll embed the function pointer directly
    uint64_t mallocAddr = reinterpret_cast<uint64_t>(&malloc_wrapper);
    cb->mov(x86::rax, mallocAddr);
    cb->call(x86::rax);
    
    // Store the allocated memory address in r15
    cb->mov(x86::r15, x86::rax);
    
    // Zero out the allocated memory
    cb->mov(x86::rdi, x86::r15);         // destination
    cb->mov(x86::rsi, 0);                // value to fill (0)
    cb->mov(x86::rdx, scope->totalSize); // count
    
    // Call memset - embed function pointer
    uint64_t memsetAddr = reinterpret_cast<uint64_t>(&memset);
    cb->mov(x86::rax, memsetAddr);
    cb->call(x86::rax);
    
    currentScope = scope;
}

void CodeGenerator::generateLexicalScope(LexicalScopeNode* scope) {
    // Allocate memory for this scope
    allocateScope(scope);
    
    // Handle function hoisting - create closures for all functions using efficient variables map
    for (const auto& [name, varInfo] : scope->variables) {
        if (varInfo.type == DataType::CLOSURE && varInfo.funcNode) {
            auto funcDecl = varInfo.funcNode;
            // Create function label and store address in closure
            createFunctionLabel(funcDecl);
            storeFunctionAddressInClosure(funcDecl, scope);
        }
    }
    
    // Process all NON-FUNCTION children first (main program logic)
    for (auto& child : scope->children) {
        if (child->type != AstNodeType::FUNCTION_DECL) {
            visitNode(child.get());
        }
    }
    
    // Add return instruction to end main program execution before function definitions
    // Only do this for the root scope to avoid returns in nested scopes
    if (scope->depth == 0) {
        cb->mov(x86::eax, 0); // Return 0 for main program
        cb->ret();
    }
    
    // Then generate function bodies AFTER main program logic
    for (auto& child : scope->children) {
        if (child->type == AstNodeType::FUNCTION_DECL) {
            visitNode(child.get());
        }
    }
}

void CodeGenerator::generateVarDecl(VarDeclNode* varDecl) {
    // For now, we expect a literal assignment
    // var x: int64 = 10
    if (varDecl->children.empty()) {
        throw std::runtime_error("Variable declaration without assignment not supported");
    }
    
    // Load the value into a register
    loadValue(varDecl->children[0].get(), x86::rax);
    
    // Store the value in the current scope
    storeVariableInScope(varDecl->varName, x86::rax, currentScope);
}

void CodeGenerator::assignVariable(VarDeclNode* varDecl, ASTNode* value) {
    // Load the value into rax
    loadValue(value, x86::rax);
    
    // Store in the lexical scope at the variable's offset
    storeVariableInScope(varDecl->varName, x86::rax, currentScope);
}

void CodeGenerator::loadValue(ASTNode* valueNode, x86::Gp destReg) {
    if (!valueNode) return;
    
    switch (valueNode->type) {
        case AstNodeType::LITERAL: {
            // Parse the literal value and load it
            int64_t value = std::stoll(valueNode->value);
            cb->mov(destReg, value);
            break;
        }
        case AstNodeType::IDENTIFIER: {
            // Load variable from scope
            loadVariableFromScope(static_cast<IdentifierNode*>(valueNode), destReg);
            break;
        }
        case AstNodeType::FUNCTION_CALL: {
            // Generate function call and load result into destReg
            generateFunctionCall(static_cast<FunctionCallNode*>(valueNode));
            // Function call result is in rax, move to destReg if different
            if (destReg.id() != x86::rax.id()) {
                cb->mov(destReg, x86::rax);
            }
            break;
        }
        default:
            throw std::runtime_error("Unsupported value node type in loadValue");
    }
}

void CodeGenerator::storeVariableInScope(const std::string& varName, x86::Gp valueReg, LexicalScopeNode* scope) {
    // Find the variable in the scope
    auto it = scope->variables.find(varName);
    if (it == scope->variables.end()) {
        throw std::runtime_error("Variable not found in scope: " + varName);
    }
    
    int offset = it->second.offset;
    std::cout << "Storing variable '" << varName << "' at offset " << offset << " in scope" << std::endl;
    
    // Store the value at [r15 + offset]
    cb->mov(x86::ptr(x86::r15, offset), valueReg);
}

x86::Gp CodeGenerator::getParameterByIndex(int paramIndex) {
    // System V ABI parameter registers: rdi, rsi, rdx, rcx, r8, r9
    x86::Gp paramRegs[] = {x86::rdi, x86::rsi, x86::rdx, x86::rcx, x86::r8, x86::r9};
    const int maxRegParams = 6;
    
    if (paramIndex < maxRegParams) {
        // Parameter is in a register
        std::cout << "Parameter " << paramIndex << " is in register" << std::endl;
        return paramRegs[paramIndex];
    } else {
        // Parameter is on stack - load it into a temporary register (rax)
        std::cout << "Parameter " << paramIndex << " is on stack, loading to rax" << std::endl;
        
        // Calculate stack offset for this parameter
        // Stack layout: [return_addr][saved_rbp][saved_r15][stack_params...]
        int stackOffset = 24 + (paramIndex - maxRegParams) * 8;
        cb->mov(x86::rax, x86::ptr(x86::rbp, stackOffset));
        
        return x86::rax;
    }
}

void CodeGenerator::loadVariableFromScope(IdentifierNode* identifier, x86::Gp destReg, int offsetInVariable) {
    if (!identifier->varRef) {
        throw std::runtime_error("Variable reference not analyzed: " + identifier->value);
    }
    
    // Get the variable access information
    auto access = identifier->getVariableAccess();
    
    if (access.scopeParameterIndex == -1) {
        // Variable is in current scope (r15)
        std::cout << "Loading variable '" << identifier->value << "' from current scope at offset " << access.offset << " with additional offset " << offsetInVariable << std::endl;
        cb->mov(destReg, x86::ptr(x86::r15, access.offset + offsetInVariable));
    } else {
        // Variable is in a parent scope - get the parameter by index and load from that scope
        std::cout << "Loading variable '" << identifier->value << "' from parent scope parameter index " << access.scopeParameterIndex << " at offset " << access.offset << " with additional offset " << offsetInVariable << std::endl;
        
        x86::Gp parentScopeReg = getParameterByIndex(access.scopeParameterIndex);
        cb->mov(destReg, x86::ptr(parentScopeReg, access.offset + offsetInVariable));
    }
}

void CodeGenerator::generatePrintStmt(ASTNode* printStmt) {
    if (printStmt->children.empty()) {
        throw std::runtime_error("Print statement without argument");
    }
    
    ASTNode* arg = printStmt->children[0].get();
    
    // Load the value to print into rdi (first argument register)
    if (arg->type == AstNodeType::IDENTIFIER) {
        loadVariableFromScope(static_cast<IdentifierNode*>(arg), x86::rdi);
    } else {
        loadValue(arg, x86::rdi);
    }
    
    // Call the print function
    std::cout << "Generating call to print_int64" << std::endl;
    
    // Call the external print function
    uint64_t printAddr = reinterpret_cast<uint64_t>(&print_int64);
    cb->mov(x86::rax, printAddr);
    cb->call(x86::rax);
}

void CodeGenerator::printInt64(IdentifierNode* identifier) {
    // Load the variable value into rdi (first argument for calling convention)
    loadVariableFromScope(identifier, x86::rdi);
    
    std::cout << "Generating call to print_int64" << std::endl;
    
    // Call the external print function
    uint64_t printAddr = reinterpret_cast<uint64_t>(&print_int64);
    cb->mov(x86::rax, printAddr);
    cb->call(x86::rax);
}

void CodeGenerator::disassembleAndPrint(void* code, size_t codeSize) {
    cs_insn* insn;
    size_t count = cs_disasm(capstoneHandle, 
                            static_cast<const uint8_t*>(code), 
                            codeSize, 
                            reinterpret_cast<uint64_t>(code), 
                            0, 
                            &insn);
    
    if (count > 0) {
        std::cout << "\n=== Disassembled Code ===" << std::endl;
        for (size_t i = 0; i < count; i++) {
            printf("0x%016lx:  %-12s %s\n", 
                   insn[i].address, 
                   insn[i].mnemonic, 
                   insn[i].op_str);
        }
        std::cout << "=========================\n" << std::endl;
        cs_free(insn, count);
    } else {
        std::cout << "Failed to disassemble code" << std::endl;
    }
}

void CodeGenerator::generateFunctionDecl(FunctionDeclNode* funcDecl) {
    std::cout << "Generating function: " << funcDecl->funcName << std::endl;
    
    // The label should already exist from hoisting phase
    Label* funcLabel = static_cast<Label*>(funcDecl->asmjitLabel);
    if (!funcLabel) {
        throw std::runtime_error("Function label not found for hoisted function: " + funcDecl->funcName);
    }
    
    // Bind the function label (start of actual function code)
    cb->bind(*funcLabel);
    
    // Generate function prologue (now includes scope allocation and parameter copying)
    generateFunctionPrologue(funcDecl);
    
    // Set this function as current scope for variable access
    LexicalScopeNode* previousScope = currentScope;
    currentScope = funcDecl;
    
    // Generate the function body
    for (auto& child : funcDecl->children) {
        visitNode(child.get());
    }
    
    // Generate function epilogue
    generateFunctionEpilogue(funcDecl);
    
    // Restore previous scope
    currentScope = previousScope;
}

void CodeGenerator::createFunctionLabel(FunctionDeclNode* funcDecl) {
    // Create a new label for this function
    Label funcLabel = cb->newLabel();
    funcDecl->asmjitLabel = new Label(funcLabel);
    
    std::cout << "Created label for function: " << funcDecl->funcName << std::endl;
}

void CodeGenerator::generateFunctionPrologue(FunctionDeclNode* funcDecl) {
    std::cout << "Generating prologue for function: " << funcDecl->funcName << std::endl;
    
    // Standard function prologue
    cb->push(x86::rbp);
    cb->mov(x86::rbp, x86::rsp);
    
    // Save r15 (current scope pointer) 
    cb->push(x86::r15);
    
    // System V ABI parameter registers: rdi, rsi, rdx, rcx, r8, r9, then stack
    x86::Gp paramRegs[] = {x86::rdi, x86::rsi, x86::rdx, x86::rcx, x86::r8, x86::r9};
    const int maxRegParams = 6;
    
    // FIRST: Save parameter registers to stack before malloc/memset clobbers them
    std::cout << "Saving " << funcDecl->paramsInfo.size() << " parameters to stack temporarily" << std::endl;
    for (size_t i = 0; i < funcDecl->paramsInfo.size() && i < maxRegParams; i++) {
        std::cout << "  Saving parameter " << i << " from register to stack" << std::endl;
        cb->push(paramRegs[i]);
    }
    
    // NOW: Allocate the function's lexical scope (this calls malloc/memset which clobbers registers)
    allocateScope(funcDecl);
    
    // FINALLY: Copy parameters from stack and original stack locations to their final locations in scope
    std::cout << "Copying " << funcDecl->paramsInfo.size() << " parameters to scope" << std::endl;
    
    // Copy register parameters (in reverse order since we pushed them)
    for (int i = std::min((int)funcDecl->paramsInfo.size(), maxRegParams) - 1; i >= 0; i--) {
        const VariableInfo& param = funcDecl->paramsInfo[i];
        int offset = param.offset;
        
        std::cout << "  Parameter " << i << " (" << param.name << ") -> scope[" << offset << "] (from stack)" << std::endl;
        
        // Pop the saved parameter from stack and store in scope
        cb->pop(x86::rax);
        cb->mov(x86::ptr(x86::r15, offset), x86::rax);
    }
    
    // Copy stack parameters (if any) - these weren't clobbered by malloc
    for (size_t i = maxRegParams; i < funcDecl->paramsInfo.size(); i++) {
        const VariableInfo& param = funcDecl->paramsInfo[i];
        int offset = param.offset;
        
        std::cout << "  Parameter " << i << " (" << param.name << ") -> scope[" << offset << "] (from original stack)" << std::endl;
        
        // Calculate stack offset - need to account for the additional pushes we did
        // Original stack: [return_addr][saved_rbp][saved_r15][stack_params...]
        // Plus we pushed register params: [saved_reg_params...][return_addr][saved_rbp][saved_r15][stack_params...]
        int regParamCount = std::min((int)funcDecl->paramsInfo.size(), maxRegParams);
        int stackOffset = 24 + (regParamCount * 8) + (i - maxRegParams) * 8;
        cb->mov(x86::rax, x86::ptr(x86::rbp, stackOffset));
        cb->mov(x86::ptr(x86::r15, offset), x86::rax);
    }
    
    // Copy hidden parameters (parent scope pointers) after regular parameters
    std::cout << "Copying " << funcDecl->hiddenParamsInfo.size() << " hidden parameters to scope" << std::endl;
    
    for (size_t i = 0; i < funcDecl->hiddenParamsInfo.size(); i++) {
        const ParameterInfo& hiddenParam = funcDecl->hiddenParamsInfo[i];
        size_t paramIndex = funcDecl->paramsInfo.size() + i; // Hidden params come after regular params
        int offset = hiddenParam.offset;
        
        std::cout << "  Hidden parameter " << i << " (depth " << hiddenParam.depth << ") -> scope[" << offset << "]" << std::endl;
        
        if (paramIndex < maxRegParams) {
            // Hidden parameter is in register
            cb->mov(x86::ptr(x86::r15, offset), paramRegs[paramIndex]);
        } else {
            // Hidden parameter is on stack
            int stackOffset = 24 + (paramIndex - maxRegParams) * 8;
            cb->mov(x86::rax, x86::ptr(x86::rbp, stackOffset));
            cb->mov(x86::ptr(x86::r15, offset), x86::rax);
        }
    }
}

void CodeGenerator::generateFunctionEpilogue(FunctionDeclNode* funcDecl) {
    std::cout << "Generating epilogue for function: " << funcDecl->funcName << std::endl;
    
    // Free the current scope memory
    cb->mov(x86::rdi, x86::r15);  // scope pointer to free
    uint64_t freeAddr = reinterpret_cast<uint64_t>(&free_wrapper);
    cb->mov(x86::rax, freeAddr);
    cb->call(x86::rax);
    
    // Restore r15 (previous scope pointer)
    cb->pop(x86::r15);
    
    // Standard function epilogue
    cb->mov(x86::rsp, x86::rbp);
    cb->pop(x86::rbp);
    cb->ret();
}

void CodeGenerator::storeFunctionAddressInClosure(FunctionDeclNode* funcDecl, LexicalScopeNode* scope) {
    // Find the closure variable for this function in the current scope
    auto it = scope->variables.find(funcDecl->funcName);
    if (it == scope->variables.end() || it->second.type != DataType::CLOSURE) {
        return; // Function not referenced as closure in this scope
    }
    
    std::cout << "Storing function address for closure: " << funcDecl->funcName << std::endl;
    
    // Get the label for this function
    Label* funcLabel = static_cast<Label*>(funcDecl->asmjitLabel);
    if (!funcLabel) {
        throw std::runtime_error("Function label not created for: " + funcDecl->funcName);
    }
    
    // Get the address of the label by using lea with a RIP-relative reference
    // This creates a memory operand that references the label
    cb->lea(x86::rax, x86::ptr(*funcLabel));
    
    // Store the function address in the closure at the variable's offset
    int offset = it->second.offset;
    cb->mov(x86::ptr(x86::r15, offset), x86::rax);

    // now store any needed closure addresses for parent scopes allNeeded
    // loop through allNeeded
    for (const auto& neededDepth : funcDecl->allNeeded) {
        // find parameter index in scopeDepthToParentParameterIndexMap
        auto it = scope->scopeDepthToParentParameterIndexMap.find(neededDepth);
        if (it == scope->scopeDepthToParentParameterIndexMap.end()) {
            throw std::runtime_error("Needed variable not found in scope: " + std::to_string(neededDepth));
        }
        // r14 value if -1
        if (it->second == -1) {
            cb->mov(x86::ptr(x86::r15, offset), x86::r14); // parent scope address
            continue;
        } 
        // cast to FunctionDeclNode
        auto funcDeclParent = dynamic_cast<FunctionDeclNode*>(scope);

        // index - paramsInfo.size() gives the hidden parameter index in hiddenParamsInfo
        int hiddenParamIndex = it->second - funcDeclParent->paramsInfo.size();
        if (hiddenParamIndex < 0 || hiddenParamIndex >= static_cast<int>(funcDeclParent->hiddenParamsInfo.size())) {
            throw std::runtime_error("Hidden parameter index out of range for needed variable: " + neededDepth);
        }
        int hiddenParamOffset = funcDeclParent->hiddenParamsInfo[hiddenParamIndex].offset;
        cb->mov(x86::rax, x86::ptr(x86::r14, hiddenParamOffset)); // load parent scope address
        cb->mov(x86::ptr(x86::r15, offset), x86::rax); // store in closure
    }
}

void CodeGenerator::generateFunctionCall(FunctionCallNode* funcCall) {
    std::cout << "Generating function call: " << funcCall->value << std::endl;
    
    // Get the function address from the closure stored in the current scope
    auto access = funcCall->getVariableAccess();
    int funcAddrOffset = -1; // Initialize function address offset
    
    if (access.scopeParameterIndex == -1) {
        // Function is in current scope - load address from closure variable
        auto it = currentScope->variables.find(funcCall->value);
        if (it == currentScope->variables.end() || it->second.type != DataType::CLOSURE) {
            throw std::runtime_error("Function not found or not a closure: " + funcCall->value);
        }
        
        // Store function address offset for later use (don't load yet to avoid clobbering)
        funcAddrOffset = it->second.offset;
        std::cout << "Function address will be loaded from r15+" << funcAddrOffset << std::endl;
        
    } else {
        // Function is in parent scope - not implemented yet
        throw std::runtime_error("Parent scope function calls not implemented yet");
    }
    
    // System V ABI: rdi, rsi, rdx, rcx, r8, r9, then stack
    x86::Gp paramRegs[] = {x86::rdi, x86::rsi, x86::rdx, x86::rcx, x86::r8, x86::r9};
    const int maxRegParams = 6;
    
    // Evaluate and pass arguments
    std::cout << "Passing " << funcCall->args.size() << " arguments" << std::endl;
    
    // Count stack parameters for alignment
    int stackParams = 0;
    if (funcCall->args.size() > maxRegParams) {
        stackParams = funcCall->args.size() - maxRegParams;
    }
    
    // Ensure stack is 16-byte aligned before call (stack params are 8 bytes each)
    if (stackParams % 2 == 1) {
        cb->sub(x86::rsp, 8); // Add padding for alignment
    }
    
    // Push stack parameters in reverse order (right to left)
    for (int i = funcCall->args.size() - 1; i >= maxRegParams; i--) {
        ASTNode* arg = funcCall->args[i].get();
        
        if (arg->type == AstNodeType::IDENTIFIER) {
            loadVariableFromScope(static_cast<IdentifierNode*>(arg), x86::rax);
        } else {
            loadValue(arg, x86::rax);
        }
        
        cb->push(x86::rax);
        std::cout << "  Stack arg " << (i - maxRegParams) << ": pushed" << std::endl;
    }
    
    // Load arguments into registers
    for (size_t i = 0; i < funcCall->args.size() && i < maxRegParams; i++) {
        ASTNode* arg = funcCall->args[i].get();
        
        std::cout << "  Register arg " << i << " -> register " << i << std::endl;
        
        if (arg->type == AstNodeType::IDENTIFIER) {
            loadVariableFromScope(static_cast<IdentifierNode*>(arg), paramRegs[i]);
        } else {
            loadValue(arg, paramRegs[i]);
        }
    }
    
    // TODO: Add hidden parameters (parent scope pointers) after regular arguments
    // For now, we're not implementing lexical scope capture in function calls
    
    // Save current r15 before function call
    cb->push(x86::r15);
    
    // Now load the function address from closure (after all register setup is done)
    cb->mov(x86::rax, x86::ptr(x86::r15, funcAddrOffset));
    
    // Indirect call through function address loaded from closure
    cb->call(x86::rax);
    
    // Restore r15 after function call
    cb->pop(x86::r15);
    
    // Clean up stack parameters (if any)
    int totalStackBytes = stackParams * 8;
    if (stackParams % 2 == 1) {
        totalStackBytes += 8; // Include alignment padding
    }
    
    if (totalStackBytes > 0) {
        cb->add(x86::rsp, totalStackBytes);
        std::cout << "Cleaned up " << totalStackBytes << " bytes from stack" << std::endl;
    }
}
