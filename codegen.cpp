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
    
    // Create assembler with the code holder
    x86::Assembler assembler(&code);
    
    std::cout << "=== Generated Assembly Code ===" << std::endl;
    
    // Generate code for the program using the new assembler - let AST nodes handle their own setup
    generateProgramWithAssembler(root, assembler);
    
    std::cout << "Code size after program: " << code.codeSize() << std::endl;
    
    // Simple return for main program
    assembler.mov(x86::eax, 0); // Return 0
    assembler.ret();
    
    std::cout << "Final code size: " << code.codeSize() << std::endl;
    
    // Finalize the code
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
    x86::Assembler& asm_ref = currentAssembler ? *currentAssembler : a;
    
    // We'll resolve these at runtime by getting their addresses
    printInt64Label = asm_ref.newLabel();
    mallocLabel = asm_ref.newLabel();
    freeLabel = asm_ref.newLabel();
}

void CodeGenerator::generateProgramWithAssembler(ASTNode* root, x86::Assembler& assembler) {
    // Just delegate to existing method but store assembler reference
    currentAssembler = &assembler;
    generateProgram(root);
}

void CodeGenerator::generateProgram(ASTNode* root) {
    if (!root) {
        throw std::runtime_error("Null program root");
    }
    
    // Handle both PROGRAM nodes and LexicalScopeNode as root
    if (root->type == ::NodeType::PROGRAM) {
        // Process all children of the program
        for (auto& child : root->children) {
            visitNode(child.get());
        }
    } else if (root->type == ::NodeType::LEXICAL_SCOPE) {
        // Treat the lexical scope as the main program scope
        visitNode(root);
    } else {
        throw std::runtime_error("Invalid program root node type");
    }
}

void CodeGenerator::visitNode(ASTNode* node) {
    if (!node) return;
    
    switch (node->type) {
        case ::NodeType::PROGRAM:
        case ::NodeType::LEXICAL_SCOPE:
            generateLexicalScope(static_cast<LexicalScopeNode*>(node));
            break;
        case ::NodeType::VAR_DECL:
            generateVarDecl(static_cast<VarDeclNode*>(node));
            break;
        case ::NodeType::PRINT_STMT:
            generatePrintStmt(node);
            break;
        case ::NodeType::FUNCTION_DECL:
            generateFunctionDecl(static_cast<FunctionDeclNode*>(node));
            break;
        case ::NodeType::FUNCTION_CALL:
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
    
    x86::Assembler& asm_ref = currentAssembler ? *currentAssembler : a;
    
    // Call malloc to allocate scope
    // mov rdi, scope->totalSize (first argument)
    asm_ref.mov(x86::rdi, scope->totalSize);
    
    // Call malloc - we need to call the actual malloc function
    // For simplicity, we'll embed the function pointer directly
    uint64_t mallocAddr = reinterpret_cast<uint64_t>(&malloc_wrapper);
    asm_ref.mov(x86::rax, mallocAddr);
    asm_ref.call(x86::rax);
    
    // Store the allocated memory address in r15
    asm_ref.mov(x86::r15, x86::rax);
    
    // Zero out the allocated memory
    asm_ref.mov(x86::rdi, x86::r15);         // destination
    asm_ref.mov(x86::rsi, 0);                // value to fill (0)
    asm_ref.mov(x86::rdx, scope->totalSize); // count
    
    // Call memset - embed function pointer
    uint64_t memsetAddr = reinterpret_cast<uint64_t>(&memset);
    asm_ref.mov(x86::rax, memsetAddr);
    asm_ref.call(x86::rax);
    
    currentScope = scope;
}

void CodeGenerator::generateLexicalScope(LexicalScopeNode* scope) {
    // Allocate memory for this scope
    allocateScope(scope);
    
    // First pass: Handle function hoisting - create closures for all functions using efficient variables map
    for (const auto& [name, varInfo] : scope->variables) {
        if (varInfo.type == DataType::CLOSURE && varInfo.funcNode) {
            auto funcDecl = varInfo.funcNode;
            // Create function label and store address in closure
            createFunctionLabel(funcDecl);
            storeFunctionAddressInClosure(funcDecl, scope);
        }
    }
    
    // Second pass: Process all other children (including function bodies)
    for (auto& child : scope->children) {
        visitNode(child.get());
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
    
    x86::Assembler& asm_ref = currentAssembler ? *currentAssembler : a;
    
    switch (valueNode->type) {
        case ::NodeType::LITERAL: {
            // Parse the literal value and load it
            int64_t value = std::stoll(valueNode->value);
            asm_ref.mov(destReg, value);
            break;
        }
        case ::NodeType::IDENTIFIER: {
            // Load variable from scope
            loadVariableFromScope(static_cast<IdentifierNode*>(valueNode), destReg);
            break;
        }
        case ::NodeType::FUNCTION_CALL: {
            // Generate function call and load result into destReg
            generateFunctionCall(static_cast<FunctionCallNode*>(valueNode));
            // Function call result is in rax, move to destReg if different
            if (destReg.id() != x86::rax.id()) {
                asm_ref.mov(destReg, x86::rax);
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
    
    x86::Assembler& asm_ref = currentAssembler ? *currentAssembler : a;
    
    int offset = it->second.offset;
    std::cout << "Storing variable '" << varName << "' at offset " << offset << " in scope" << std::endl;
    
    // Store the value at [r15 + offset]
    asm_ref.mov(x86::ptr(x86::r15, offset), valueReg);
}

void CodeGenerator::loadVariableFromScope(IdentifierNode* identifier, x86::Gp destReg) {
    if (!identifier->varRef) {
        throw std::runtime_error("Variable reference not analyzed: " + identifier->value);
    }
    
    x86::Assembler& asm_ref = currentAssembler ? *currentAssembler : a;
    
    // Get the variable access information
    auto access = identifier->getVariableAccess();
    
    if (access.parameterIndex == -1) {
        // Variable is in current scope (r15)
        std::cout << "Loading variable '" << identifier->value << "' from current scope at offset " << access.offset << std::endl;
        asm_ref.mov(destReg, x86::ptr(x86::r15, access.offset));
    } else {
        // Variable is in a parent scope - would need to load from parameter
        // For now, throw an error as we're not implementing function calls yet
        throw std::runtime_error("Parent scope variable access not implemented yet: " + identifier->value);
    }
}

void CodeGenerator::generatePrintStmt(ASTNode* printStmt) {
    if (printStmt->children.empty()) {
        throw std::runtime_error("Print statement without argument");
    }
    
    x86::Assembler& asm_ref = currentAssembler ? *currentAssembler : a;
    
    ASTNode* arg = printStmt->children[0].get();
    
    // Load the value to print into rdi (first argument register)
    if (arg->type == ::NodeType::IDENTIFIER) {
        loadVariableFromScope(static_cast<IdentifierNode*>(arg), x86::rdi);
    } else {
        loadValue(arg, x86::rdi);
    }
    
    // Call the print function
    std::cout << "Generating call to print_int64" << std::endl;
    
    // Call the external print function
    uint64_t printAddr = reinterpret_cast<uint64_t>(&print_int64);
    asm_ref.mov(x86::rax, printAddr);
    asm_ref.call(x86::rax);
}

void CodeGenerator::printInt64(IdentifierNode* identifier) {
    // Load the variable value into rdi (first argument for calling convention)
    loadVariableFromScope(identifier, x86::rdi);
    
    std::cout << "Generating call to print_int64" << std::endl;
    
    // Call the external print function
    uint64_t printAddr = reinterpret_cast<uint64_t>(&print_int64);
    a.mov(x86::rax, printAddr);
    a.call(x86::rax);
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
    
    x86::Assembler& asm_ref = currentAssembler ? *currentAssembler : a;
    
    // The label should already exist from hoisting phase
    Label* funcLabel = static_cast<Label*>(funcDecl->asmjitLabel);
    if (!funcLabel) {
        throw std::runtime_error("Function label not found for hoisted function: " + funcDecl->funcName);
    }
    
    // Bind the function label (start of actual function code)
    asm_ref.bind(*funcLabel);
    
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
    x86::Assembler& asm_ref = currentAssembler ? *currentAssembler : a;
    
    // Create a new label for this function
    Label* funcLabel = new Label(asm_ref.newLabel());
    funcDecl->asmjitLabel = funcLabel;
    
    std::cout << "Created label for function: " << funcDecl->funcName << std::endl;
}

void CodeGenerator::generateFunctionPrologue(FunctionDeclNode* funcDecl) {
    x86::Assembler& asm_ref = currentAssembler ? *currentAssembler : a;
    
    std::cout << "Generating prologue for function: " << funcDecl->funcName << std::endl;
    
    // Standard function prologue
    asm_ref.push(x86::rbp);
    asm_ref.mov(x86::rbp, x86::rsp);
    
    // Save r15 (current scope pointer) 
    asm_ref.push(x86::r15);
    
    // Allocate the function's lexical scope first (moved from generateFunction)
    allocateScope(funcDecl);
    
    // Copy parameters from ABI registers/stack to their locations in the scope
    // System V ABI: rdi, rsi, rdx, rcx, r8, r9, then stack
    x86::Gp paramRegs[] = {x86::rdi, x86::rsi, x86::rdx, x86::rcx, x86::r8, x86::r9};
    const int maxRegParams = 6;
    
    std::cout << "Copying " << funcDecl->paramsInfo.size() << " parameters to scope" << std::endl;
    
    for (size_t i = 0; i < funcDecl->paramsInfo.size(); i++) {
        const VariableInfo& param = funcDecl->paramsInfo[i];
        int offset = param.offset;
        
        std::cout << "  Parameter " << i << " (" << param.name << ") -> scope[" << offset << "]" << std::endl;
        
        if (i < maxRegParams) {
            // Parameter is in register - copy to scope
            asm_ref.mov(x86::ptr(x86::r15, offset), paramRegs[i]);
        } else {
            // Parameter is on stack - calculate stack offset and copy
            // Stack parameters start at rbp+16 (8 for return address + 8 for saved rbp)
            // Each parameter is 8 bytes aligned
            int stackOffset = 16 + (i - maxRegParams) * 8;
            asm_ref.mov(x86::rax, x86::ptr(x86::rbp, stackOffset));
            asm_ref.mov(x86::ptr(x86::r15, offset), x86::rax);
        }
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
            asm_ref.mov(x86::ptr(x86::r15, offset), paramRegs[paramIndex]);
        } else {
            // Hidden parameter is on stack
            int stackOffset = 16 + (paramIndex - maxRegParams) * 8;
            asm_ref.mov(x86::rax, x86::ptr(x86::rbp, stackOffset));
            asm_ref.mov(x86::ptr(x86::r15, offset), x86::rax);
        }
    }
}

void CodeGenerator::generateFunctionEpilogue(FunctionDeclNode* funcDecl) {
    x86::Assembler& asm_ref = currentAssembler ? *currentAssembler : a;
    
    std::cout << "Generating epilogue for function: " << funcDecl->funcName << std::endl;
    
    // Free the current scope memory
    asm_ref.mov(x86::rdi, x86::r15);  // scope pointer to free
    uint64_t freeAddr = reinterpret_cast<uint64_t>(&free_wrapper);
    asm_ref.mov(x86::rax, freeAddr);
    asm_ref.call(x86::rax);
    
    // Restore r15 (previous scope pointer)
    asm_ref.pop(x86::r15);
    
    // Standard function epilogue
    asm_ref.mov(x86::rsp, x86::rbp);
    asm_ref.pop(x86::rbp);
    asm_ref.ret();
}

void CodeGenerator::storeFunctionAddressInClosure(FunctionDeclNode* funcDecl, LexicalScopeNode* scope) {
    // Find the closure variable for this function in the current scope
    auto it = scope->variables.find(funcDecl->funcName);
    if (it == scope->variables.end() || it->second.type != DataType::CLOSURE) {
        return; // Function not referenced as closure in this scope
    }
    
    x86::Assembler& asm_ref = currentAssembler ? *currentAssembler : a;
    
    std::cout << "Storing function address for closure: " << funcDecl->funcName << std::endl;
    
    // Get the label for this function
    Label* funcLabel = static_cast<Label*>(funcDecl->asmjitLabel);
    if (!funcLabel) {
        throw std::runtime_error("Function label not created for: " + funcDecl->funcName);
    }
    
    // Load the function address using LEA (Load Effective Address)
    // This will be resolved by AsmJit when the code is finalized
    asm_ref.lea(x86::rax, x86::ptr(*funcLabel));
    
    // Store the function address in the closure at the variable's offset
    int offset = it->second.offset;
    asm_ref.mov(x86::ptr(x86::r15, offset), x86::rax);
}

void CodeGenerator::generateFunctionCall(FunctionCallNode* funcCall) {
    std::cout << "Generating function call: " << funcCall->value << std::endl;
    
    x86::Assembler& asm_ref = currentAssembler ? *currentAssembler : a;
    
    // Load the function address from the closure
    auto access = funcCall->getVariableAccess();
    
    if (access.parameterIndex == -1) {
        // Function is in current scope
        asm_ref.mov(x86::r11, x86::ptr(x86::r15, access.offset)); // Store function address in r11
    } else {
        // Function is in parent scope - load from parameter
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
        asm_ref.sub(x86::rsp, 8); // Add padding for alignment
    }
    
    // Push stack parameters in reverse order (right to left)
    for (int i = funcCall->args.size() - 1; i >= maxRegParams; i--) {
        ASTNode* arg = funcCall->args[i].get();
        
        if (arg->type == ::NodeType::IDENTIFIER) {
            loadVariableFromScope(static_cast<IdentifierNode*>(arg), x86::rax);
        } else {
            loadValue(arg, x86::rax);
        }
        
        asm_ref.push(x86::rax);
        std::cout << "  Stack arg " << (i - maxRegParams) << ": pushed" << std::endl;
    }
    
    // Load arguments into registers
    for (size_t i = 0; i < funcCall->args.size() && i < maxRegParams; i++) {
        ASTNode* arg = funcCall->args[i].get();
        
        std::cout << "  Register arg " << i << " -> register " << i << std::endl;
        
        if (arg->type == ::NodeType::IDENTIFIER) {
            loadVariableFromScope(static_cast<IdentifierNode*>(arg), paramRegs[i]);
        } else {
            loadValue(arg, paramRegs[i]);
        }
    }
    
    // TODO: Add hidden parameters (parent scope pointers) after regular arguments
    // For now, we're not implementing lexical scope capture in function calls
    
    // Save current r15 before function call
    asm_ref.push(x86::r15);
    
    // Call the function
    asm_ref.call(x86::r11);
    
    // Restore r15 after function call
    asm_ref.pop(x86::r15);
    
    // Clean up stack parameters (if any)
    int totalStackBytes = stackParams * 8;
    if (stackParams % 2 == 1) {
        totalStackBytes += 8; // Include alignment padding
    }
    
    if (totalStackBytes > 0) {
        asm_ref.add(x86::rsp, totalStackBytes);
        std::cout << "Cleaned up " << totalStackBytes << " bytes from stack" << std::endl;
    }
}
