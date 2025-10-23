#include "codegen.h"
#include "gc.h"
#include <iostream>
#include <cstdlib>
#include <cstring>
// #include "codegen_torch.h"
#include "codegen_array.h"

// External C functions implementation
extern "C" {
    void* malloc_wrapper(size_t size) {
        return malloc(size);
    }
    
    void* calloc_wrapper(size_t nmemb, size_t size) {
        return calloc(nmemb, size);
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

void Codegen::generateProgram(ASTNode& root, const std::map<std::string, ClassDeclNode*>& classRegistry, const std::vector<FunctionDeclNode*>& functionRegistry) {
    generatedFunction = generator.generateCode(&root, classRegistry, functionRegistry);
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

void* CodeGenerator::generateCode(ASTNode* root, const std::map<std::string, ClassDeclNode*>& classRegistry, const std::vector<FunctionDeclNode*>& functionRegistry) {
    // Reset and initialize code holder
    code.reset();
    code.init(rt.environment(), rt.cpuFeatures());
    
    // Create builder with the code holder
    cb = new x86::Builder(&code);
    
    // Initialize AsmLibrary with the current builder
    asmLibrary = std::make_unique<AsmLibrary>(*cb, x86::r15);
    
    std::cout << "=== Generated Assembly Code ===" << std::endl;
    
    // INITIALIZATION: Create all scope metadata at compile time before generating any code
    std::cout << "\n=== Initializing Scope Metadata (Compile Time) ===" << std::endl;
    initializeAllScopeMetadata(root, functionRegistry);
    
    // FIRST PASS: Generate all functions (including methods) upfront
    std::cout << "\n=== First Pass: Generating All Functions ===" << std::endl;
    generateAllFunctions(functionRegistry);
    
    // SECOND PASS: Generate the main program flow (this traverses the AST normally)
    // Classes will be emitted as they appear in the AST, creating closures for methods inline
    std::cout << "\n=== Second Pass: Generating Main Program ===" << std::endl;
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
    
    // NOW patch the metadata closures with actual function addresses
    patchMetadataClosures(executableFunc, classRegistry);
    
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
    callocLabel = cb->newLabel();
}

void CodeGenerator::generateAllFunctions(const std::vector<FunctionDeclNode*>& functionRegistry) {
    std::cout << "Generating " << functionRegistry.size() << " functions from registry" << std::endl;
    
    // Create labels for all functions first
    for (auto* funcDecl : functionRegistry) {
        if (!funcDecl->asmjitLabel) {
            createFunctionLabel(funcDecl);
        }
    }
    
    // Generate code for all functions
    for (auto* funcDecl : functionRegistry) {
        if (funcDecl->isMethod) {
            std::cout << "Generating method from registry: " << funcDecl->funcName 
                      << " (class: " << (funcDecl->owningClass ? funcDecl->owningClass->className : "unknown") << ")" << std::endl;
        } else {
            std::cout << "Generating function from registry: " << funcDecl->funcName << std::endl;
        }
        
        // Generate the function code
        Label* funcLabel = static_cast<Label*>(funcDecl->asmjitLabel);
        if (!funcLabel) {
            throw std::runtime_error("Function label not created for: " + funcDecl->funcName);
        }
        
        // Bind the function label
        cb->bind(*funcLabel);
        
        // Generate function prologue
        generateFunctionPrologue(funcDecl);
        
        // Set this function as current scope
        LexicalScopeNode* previousScope = currentScope;
        currentScope = funcDecl;
        
        // Handle function hoisting - create closures for nested functions in this scope
        for (const auto& [name, varInfo] : funcDecl->variables) {
            if (varInfo.type == DataType::CLOSURE && varInfo.funcNode) {
                auto childFuncDecl = varInfo.funcNode;
                // The label should already exist from the first loop above
                storeFunctionAddressInClosure(childFuncDecl, funcDecl);
            }
        }
        
        // Process the function body (skip nested functions and classes)
        for (auto& child : funcDecl->children) {
            if (child->type != AstNodeType::FUNCTION_DECL && child->type != AstNodeType::CLASS_DECL) {
                visitNode(child.get());
            }
        }
        
        // For main function, set return value
        if (funcDecl->funcName == "main") {
            cb->mov(x86::eax, 0);
        }
        
        // Generate function epilogue
        generateFunctionEpilogue(funcDecl);
        
        // Restore previous scope
        currentScope = previousScope;
    }
    
    // Generate AsmLibrary utility functions
    if (asmLibrary) {
        std::cout << "Generating AsmLibrary utility functions" << std::endl;
        asmLibrary->emitAllFunctionDefinitions();
    }
    
    std::cout << "Finished generating all functions from registry" << std::endl;
}

void CodeGenerator::generateProgram(ASTNode* root) {
    if (!root) {
        throw std::runtime_error("Null program root");
    }
    
    std::cout << "Generating program - main should already be generated from registry" << std::endl;
    
    // Root should always be a FUNCTION_DECL (the main function)
    if (root->type == AstNodeType::FUNCTION_DECL) {
        FunctionDeclNode* mainFunc = static_cast<FunctionDeclNode*>(root);
        
        // The main function should already have been generated in generateAllFunctions
        // But we still need to ensure its label exists (it should)
        if (!mainFunc->asmjitLabel) {
            throw std::runtime_error("Main function label should have been created in generateAllFunctions");
        }
        
        // Process any classes in the main function's children
        // Classes need special handling to create method closures at the class definition point
        for (auto& child : mainFunc->children) {
            if (child->type == AstNodeType::CLASS_DECL) {
                // We don't regenerate the class methods (they're already generated)
                // but we might need to do other class-related setup here
                std::cout << "Skipping class in second pass (methods already generated)" << std::endl;
            }
        }
    } else {
        throw std::runtime_error("Invalid program root node type - expected FUNCTION_DECL");
    }
}

void CodeGenerator::visitNode(ASTNode* node) {
    if (!node) return;
    
    switch (node->type) {
        case AstNodeType::VAR_DECL:
            generateVarDecl(static_cast<VarDeclNode*>(node));
            break;
        case AstNodeType::LET_DECL:
            generateLetDecl(static_cast<LetDeclNode*>(node));
            break;
        case AstNodeType::PRINT_STMT:
            generatePrintStmt(node);
            break;
        case AstNodeType::FUNCTION_DECL:
            // Function bodies are generated during the upfront function pass.
            break;
        case AstNodeType::FUNCTION_CALL:
            generateFunctionCall(static_cast<FunctionCallNode*>(node));
            break;
        case AstNodeType::METHOD_CALL:
            generateFunctionCall(static_cast<MethodCallNode*>(node));
            break;
        case AstNodeType::GO_STMT:
            generateGoStmt(static_cast<GoStmtNode*>(node));
            break;
        case AstNodeType::SETTIMEOUT_STMT:
            generateSetTimeoutStmt(static_cast<SetTimeoutStmtNode*>(node));
            break;
        case AstNodeType::BLOCK_STMT:
            generateBlockStmt(static_cast<BlockStmtNode*>(node));
            break;
        case AstNodeType::MEMBER_ASSIGN:
            generateMemberAssign(static_cast<MemberAssignNode*>(node));
            break;
        case AstNodeType::CLASS_DECL:
            generateClassDecl(static_cast<ClassDeclNode*>(node));
            break;
        case AstNodeType::BRACKET_ACCESS: {
            auto bracketAccess = static_cast<BracketAccessNode*>(node);
            if (bracketAccess->objectExpression) {
                visitNode(bracketAccess->objectExpression.get());
            }
            // Tensor segments removed; ignore segments
            break;
        }
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

    // Save parent scope register (r14) - r15 doesn't need to be saved since its value goes into r14
    cb->push(x86::r14);
    // Set r14 to current r15 (the new scope's parent will be the current scope)
    cb->mov(x86::r14, x86::r15);
    
    
    // Call calloc to allocate and zero-initialize scope
    // mov rdi, 1 (number of elements)
    cb->mov(x86::rdi, 1);
    // mov rsi, scope->totalSize (size of each element)
    cb->mov(x86::rsi, scope->totalSize);
    
    // Call calloc - we need to call the actual calloc function
    // For simplicity, we'll embed the function pointer directly
    uint64_t callocAddr = reinterpret_cast<uint64_t>(&calloc_wrapper);
    cb->mov(x86::rax, callocAddr);
    cb->call(x86::rax);
    
    
    // Store the allocated memory address in r15
    cb->mov(x86::r15, x86::rax);
    
    // Store pre-computed metadata pointer at offset 8 in the scope
    // The metadata was created at compile time, so we just load the pointer
    if (!scope->metadata) {
        throw std::runtime_error("Scope metadata not initialized at compile time!");
    }
    cb->mov(x86::r11, reinterpret_cast<uint64_t>(scope->metadata));
    cb->mov(x86::qword_ptr(x86::r15, ScopeLayout::METADATA_OFFSET), x86::r11);
    
    // Track scope as an allocated object for GC
    cb->mov(x86::rdi, x86::r15);  // First argument: scope pointer
    uint64_t gcTrackAddr = reinterpret_cast<uint64_t>(&gc_track_object);
    cb->mov(x86::r11, gcTrackAddr);
    cb->call(x86::r11);
    
    // Track scope in GC (push scope to roots)
    cb->mov(x86::rdi, x86::r15);  // First argument: scope pointer
    uint64_t gcPushScopeAddr = reinterpret_cast<uint64_t>(&gc_push_scope);
    cb->mov(x86::r11, gcPushScopeAddr);
    cb->call(x86::r11);
    
    currentScope = scope;
}

void* CodeGenerator::createScopeMetadata(LexicalScopeNode* scope) {
    if (!scope) return nullptr;
    
    // This function is now called at COMPILE TIME (during code generation setup)
    // NOT at runtime! The metadata is created once and reused for all scope allocations.
    
    // Count variables that need GC tracking (objects and closures)
    std::vector<VarMetadata> trackedVars;
    
    for (const auto& [varName, varInfo] : scope->variables) {
        // Only track object references and closures (anything that could point to heap objects)
        if (varInfo.type == DataType::OBJECT || varInfo.type == DataType::CLOSURE) {
            void* typeInfo = nullptr;
            
            // For objects, get the class metadata from the registry
            if (varInfo.type == DataType::OBJECT && varInfo.classNode) {
                typeInfo = MetadataRegistry::getInstance().getClassMetadata(varInfo.classNode->className);
            }
            
            std::cout << "  - Tracking variable '" << varName << "' of type " 
                      << (varInfo.type == DataType::OBJECT ? "OBJECT" : "CLOSURE")
                      << " at offset " << varInfo.offset << std::endl;
            
            // Note: offset in VariableInfo is already adjusted for ScopeLayout::DATA_OFFSET
            // But we need the offset relative to data start for the metadata
            trackedVars.emplace_back(varInfo.offset, varInfo.type, typeInfo);
        }
    }
    
    // Allocate metadata structure ONCE at compile time
    ScopeMetadata* metadata = new ScopeMetadata();
    metadata->numVars = trackedVars.size();
    
    if (metadata->numVars > 0) {
        metadata->vars = new VarMetadata[metadata->numVars];
        for (int i = 0; i < metadata->numVars; i++) {
            metadata->vars[i] = trackedVars[i];
        }
    } else {
        metadata->vars = nullptr;
    }
    
    std::cout << "Created scope metadata at compile time with " << metadata->numVars << " tracked variables" << std::endl;
    
    return metadata;
}

void CodeGenerator::initializeAllScopeMetadata(ASTNode* root, const std::vector<FunctionDeclNode*>& functionRegistry) {
    std::cout << "Initializing scope metadata for all scopes at compile time..." << std::endl;
    
    // Process all functions in the registry (includes methods)
    for (auto* funcDecl : functionRegistry) {
        // Create metadata for the function scope itself
        if (!funcDecl->metadata) {
            funcDecl->metadata = createScopeMetadata(funcDecl);
            std::cout << "  Created metadata for function: " << funcDecl->funcName << std::endl;
        }
        
        // Recursively process all nested scopes (blocks) within this function
        initializeScopeMetadataRecursive(funcDecl);
    }
    
    std::cout << "Scope metadata initialization complete!" << std::endl;
}

void CodeGenerator::initializeScopeMetadataRecursive(ASTNode* node) {
    if (!node) return;
    
    // If this is a lexical scope (block), create its metadata
    if (node->type == AstNodeType::BLOCK_STMT) {
        BlockStmtNode* block = static_cast<BlockStmtNode*>(node);
        if (!block->metadata) {
            block->metadata = createScopeMetadata(block);
            std::cout << "    Created metadata for block at depth " << block->depth << std::endl;
        }
    }
    
    // Recursively process children (skip nested functions - they're handled in the main loop)
    for (auto& child : node->children) {
        if (child->type != AstNodeType::FUNCTION_DECL && child->type != AstNodeType::CLASS_DECL) {
            initializeScopeMetadataRecursive(child.get());
        }
    }
}

void CodeGenerator::generateVarDecl(VarDeclNode* varDecl) {
    // For now, we expect a literal assignment
    // var x: int64 = 10
    if (varDecl->children.empty()) {
        throw std::runtime_error("Variable declaration without assignment not supported");
    }

    if (varDecl->isArray) {
        if (varDecl->varType != DataType::ANY) {
            throw std::runtime_error("Array variable ANY not implemented yet");
        }
        if (varDecl->varType == DataType::INT64) {
            auto makeArrayAddr = reinterpret_cast<uint64_t>(&makeArray<int64_t>);
            cb->mov(x86::rdi, static_cast<uint32_t>(varDecl->varType)); // first argument: DataType
            cb->mov(x86::rax, makeArrayAddr);
            cb->call(x86::rax);
            // store result in variable
            storeVariableInScope(varDecl->varName, x86::rax, currentScope, varDecl);
        } else {
            throw std::runtime_error("Array variable type not implemented yet");
        }
        // // get pointer to makeTensor
        // auto tensorFuncAddr = reinterpret_cast<uint64_t>(&makeTensor);
        // cb->mov(x86::rdi, static_cast<uint32_t>(varDecl->varType)); // first argument: DataType
        // cb->mov(x86::rax, tensorFuncAddr);
        // cb->call(x86::rax);
        // // store result in variable
        // storeVariableInScope(varDecl->varName, x86::rax, currentScope, varDecl);
    } else {
        ASTNode* valueNode = varDecl->children[0].get();
        if (varDecl->varType == DataType::ANY) {
            loadAnyValue(valueNode, x86::rax, x86::rdx);
            storeVariableInScope(varDecl->varName, x86::rax, currentScope, valueNode, x86::rdx);
        } else {
            // Load the value into a register using declared type
            loadValue(valueNode, x86::rax, x86::r15, varDecl->varType);
            storeVariableInScope(varDecl->varName, x86::rax, currentScope, valueNode);
        }
    }
}

void CodeGenerator::generateLetDecl(LetDeclNode* letDecl) {
    std::cout << "Generating let declaration: " << letDecl->varName << std::endl;
    
    // Let declarations work the same as var declarations
    // let x: int64 = 10
    if (letDecl->children.empty()) {
        throw std::runtime_error("Let declaration without assignment not supported");
    }
    
    ASTNode* valueNode = letDecl->children[0].get();
    
    // Load the value into a register using declared type
    loadValue(valueNode, x86::rax, x86::r15, letDecl->varType);
    
    // Store the value in the current scope
    storeVariableInScope(letDecl->varName, x86::rax, currentScope, valueNode);
}

void CodeGenerator::assignVariable(VarDeclNode* varDecl, ASTNode* value) {
    // Load the value into rax using declared type
    loadValue(value, x86::rax, x86::r15, varDecl->varType);
    
    // Store in the lexical scope at the variable's offset
    storeVariableInScope(varDecl->varName, x86::rax, currentScope, value);
}

void CodeGenerator::loadValue(ASTNode* valueNode, x86::Gp destReg, x86::Gp sourceScopeReg, std::optional<DataType> expectedType) {
    if (!valueNode) return;
    
    std::cout << "DEBUG loadValue: node type = " << static_cast<int>(valueNode->type) << std::endl;
    
    switch (valueNode->type) {
        case AstNodeType::LITERAL: {
            auto* literal = static_cast<LiteralNode*>(valueNode);
            DataType parseType = expectedType.value_or(DataType::INT64);
            switch (parseType) {
                case DataType::INT32: {
                    if (literal->literalKind == LiteralType::STRING) {
                        throw std::runtime_error("Expected numeric literal for int32");
                    }
                    int64_t value = std::stoll(literal->value);
                    cb->mov(destReg, static_cast<int32_t>(value));
                    break;
                }
                case DataType::INT64: {
                    if (literal->literalKind == LiteralType::STRING) {
                        throw std::runtime_error("Expected numeric literal for int64");
                    }
                    int64_t value = std::stoll(literal->value);
                    cb->mov(destReg, value);
                    break;
                }
                case DataType::FLOAT64: {
                    if (literal->literalKind == LiteralType::STRING) {
                        throw std::runtime_error("Expected numeric literal for float64");
                    }
                    double value = std::stod(literal->value);
                    uint64_t bits;
                    std::memcpy(&bits, &value, sizeof(bits));
                    cb->mov(destReg, bits);
                    break;
                }
                case DataType::ANY: {
                    if (literal->literalKind == LiteralType::STRING) {
                        throw std::runtime_error("String literal not supported for any without explicit handling");
                    }
                    double value = std::stod(literal->value);
                    uint64_t bits;
                    std::memcpy(&bits, &value, sizeof(bits));
                    cb->mov(destReg, bits);
                    break;
                }
                case DataType::STRING: {
                    if (literal->literalKind != LiteralType::STRING) {
                        throw std::runtime_error("Expected string literal for string type");
                    }
                    uint64_t strAddr = reinterpret_cast<uint64_t>(literal->value.c_str());
                    cb->mov(destReg, strAddr);
                    break;
                }
                default:
                    throw std::runtime_error("Unsupported expected type for literal");
            }
            break;
        }
        case AstNodeType::IDENTIFIER: {
            // Load variable from scope (using provided source scope register)
            loadVariableFromScope(static_cast<IdentifierNode*>(valueNode), destReg, 0, sourceScopeReg);
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
        case AstNodeType::AWAIT_EXPR: {
            // Handle await expression
            generateAwaitExpr(valueNode, destReg);
            break;
        }
        case AstNodeType::SLEEP_CALL: {
            // Handle sleep call
            generateSleepCall(valueNode, destReg);
            break;
        }
        case AstNodeType::NEW_EXPR: {
            // Handle new expression
            generateNewExpr(static_cast<NewExprNode*>(valueNode), destReg);
            break;
        }
        case AstNodeType::MEMBER_ACCESS: {
            // Handle member access
            generateMemberAccess(static_cast<MemberAccessNode*>(valueNode), destReg);
            break;
        }
        case AstNodeType::THIS_EXPR: {
            // Handle 'this' expression - load from first parameter
            // 'this' is always the first parameter in a method
            // It's stored in the scope like any other variable
            
            // Create a temporary identifier node to load 'this' variable
            IdentifierNode tempIdentifier("this");
            tempIdentifier.varRef = nullptr;
            tempIdentifier.accessedIn = currentScope;
            
            // Find 'this' in the current scope
            auto it = currentScope->variables.find("this");
            if (it == currentScope->variables.end()) {
                throw std::runtime_error("'this' not found in method scope");
            }
            tempIdentifier.varRef = &it->second;
            
            // Load 'this' from scope (using provided source scope register)
            loadVariableFromScope(&tempIdentifier, destReg, 0, sourceScopeReg);
            break;
        }
        default:
            std::cout << "DEBUG loadValue: Unsupported node type " << static_cast<int>(valueNode->type) << std::endl;
            throw std::runtime_error("Unsupported value node type in loadValue");
    }
}

void CodeGenerator::loadAnyValue(ASTNode* valueNode, x86::Gp valueReg, x86::Gp typeReg, x86::Gp sourceScopeReg) {
    if (!valueNode) {
        throw std::runtime_error("Null value node for any load");
    }
    
    switch (valueNode->type) {
        case AstNodeType::LITERAL: {
            auto* literal = static_cast<LiteralNode*>(valueNode);
            if (literal->literalKind == LiteralType::STRING) {
                throw std::runtime_error("String literal not yet supported in any value");
            }
            double floatValue = std::stod(literal->value);
            uint64_t bits;
            std::memcpy(&bits, &floatValue, sizeof(bits));
            cb->mov(valueReg, bits);
            cb->mov(typeReg, static_cast<uint32_t>(DataType::FLOAT64));
            break;
        }
        case AstNodeType::IDENTIFIER: {
            auto* identifier = static_cast<IdentifierNode*>(valueNode);
            if (!identifier->varRef) {
                throw std::runtime_error("Identifier not analyzed for any load: " + identifier->value);
            }
            
            switch (identifier->varRef->type) {
                case DataType::ANY:
                    loadVariableFromScope(identifier, typeReg, 0, sourceScopeReg);
                    loadVariableFromScope(identifier, valueReg, 8, sourceScopeReg);
                    break;
                case DataType::INT32:
                case DataType::INT64:
                case DataType::FLOAT64:
                case DataType::OBJECT:
                    loadVariableFromScope(identifier, valueReg, 0, sourceScopeReg);
                    cb->mov(typeReg, static_cast<uint32_t>(identifier->varRef->type));
                    break;
                default:
                    throw std::runtime_error("Unsupported identifier type for any value: " + identifier->value);
            }
            break;
        }
        case AstNodeType::NEW_EXPR: {
            generateNewExpr(static_cast<NewExprNode*>(valueNode), valueReg);
            cb->mov(typeReg, static_cast<uint32_t>(DataType::OBJECT));
            break;
        }
        case AstNodeType::MEMBER_ACCESS: {
            auto* memberAccess = static_cast<MemberAccessNode*>(valueNode);
            if (!memberAccess->classRef) {
                throw std::runtime_error("Class reference missing for member access in any value");
            }
            auto fieldIt = memberAccess->classRef->fields.find(memberAccess->memberName);
            if (fieldIt == memberAccess->classRef->fields.end()) {
                throw std::runtime_error("Field not found for member access in any value: " + memberAccess->memberName);
            }
            DataType fieldType = fieldIt->second.type;
            
            x86::Gp objectReg = x86::r11;
            loadValue(memberAccess->object.get(), objectReg);
            
            if (fieldType == DataType::ANY) {
                cb->mov(typeReg, x86::qword_ptr(objectReg, memberAccess->memberOffset));
                cb->mov(valueReg, x86::qword_ptr(objectReg, memberAccess->memberOffset + 8));
            } else {
                generateMemberAccess(memberAccess, valueReg);
                cb->mov(typeReg, static_cast<uint32_t>(fieldType));
            }
            break;
        }
        default:
            throw std::runtime_error("Unsupported node type for any value");
    }
}

void CodeGenerator::storeVariableInScope(const std::string& varName, x86::Gp valueReg, LexicalScopeNode* scope, ASTNode* valueNode, x86::Gp typeReg) {
    // Find the variable in the scope
    auto it = scope->variables.find(varName);
    if (it == scope->variables.end()) {
        throw std::runtime_error("Variable not found in scope: " + varName);
    }
    
    int offset = it->second.offset;
    std::cout << "Storing variable '" << varName << "' at offset " << offset << " in scope" << std::endl;
    
    if (it->second.type == DataType::ANY) {
        cb->mov(x86::ptr(x86::r15, offset), typeReg);
        cb->mov(x86::ptr(x86::r15, offset + 8), valueReg);
        
        // If we're storing an object reference that's not a NEW expression, run the write barrier
        if (valueNode && valueNode->type != AstNodeType::NEW_EXPR) {
            Label skipObjectBarrier = cb->newLabel();
            cb->cmp(typeReg, static_cast<uint32_t>(DataType::OBJECT));
            cb->jne(skipObjectBarrier);
            
            cb->mov(x86::rcx, x86::qword_ptr(valueReg, ObjectLayout::FLAGS_OFFSET));  // Load flags
            cb->test(x86::rcx, ObjectFlags::NEEDS_SET_FLAG);
            
            Label skipWriteBarrier = cb->newLabel();
            cb->jz(skipWriteBarrier);  // Jump if NEEDS_SET_FLAG not set
            
            cb->or_(x86::qword_ptr(valueReg, ObjectLayout::FLAGS_OFFSET), ObjectFlags::SET_FLAG);
            cb->mfence();
            
            cb->bind(skipWriteBarrier);
            cb->bind(skipObjectBarrier);
        }
        return;
    }
    
    // Store the value at [r15 + offset]
    cb->mov(x86::ptr(x86::r15, offset), valueReg);
    
    // If this is an object-typed variable and not a NEW expression, handle GC write barrier inline
    if (it->second.type == DataType::OBJECT && valueNode && valueNode->type != AstNodeType::NEW_EXPR) {
        // Inline GC write barrier - check needs_set_flag and atomically set set_flag if needed
        // This is much faster than a function call
        
        // Load flags from object header (at offset 8)
        // flags is at [valueReg + 8]
        cb->mov(x86::rcx, x86::qword_ptr(valueReg, ObjectLayout::FLAGS_OFFSET));  // Load flags
        
        // Test if NEEDS_SET_FLAG (bit 0) is set
        cb->test(x86::rcx, ObjectFlags::NEEDS_SET_FLAG);
        
        // Create a label for skipping if not needed
        Label skipWriteBarrier = cb->newLabel();
        cb->jz(skipWriteBarrier);  // Jump if zero (NEEDS_SET_FLAG not set)
        
        // NEEDS_SET_FLAG is set, so OR the SET_FLAG bit (no LOCK needed - idempotent)
        // Using non-locked OR is safe because we're only setting a bit to 1
        cb->or_(x86::qword_ptr(valueReg, ObjectLayout::FLAGS_OFFSET), ObjectFlags::SET_FLAG);
        
        // Memory fence to ensure write visibility to GC thread
        // This guarantees the set_flag write is visible before GC reads it in phase 3
        cb->mfence();
        
        cb->bind(skipWriteBarrier);
    }
}

void CodeGenerator::loadParameterIntoRegister(int paramIndex, x86::Gp destReg, x86::Gp scopeReg) {
    // Load a parameter from the specified scope. Parameters can be:
    // - For functions: regular parameters + hidden parameters (parent scope pointers)
    // - For blocks: only hidden parameters (parent scope pointers)
    
    if (auto currentFunc = dynamic_cast<FunctionDeclNode*>(currentScope)) {
        // Current scope is a function
        size_t totalRegularParams = currentFunc->paramsInfo.size();
        
        if (static_cast<size_t>(paramIndex) < totalRegularParams) {
            // This is a regular parameter - load from its scope offset
            const VariableInfo& param = currentFunc->paramsInfo[paramIndex];
            std::cout << "Loading regular parameter " << paramIndex << " from scope offset " << param.offset << " using scope register" << std::endl;
            cb->mov(destReg, x86::ptr(scopeReg, param.offset));
        } else {
            // This is a hidden parameter - load from its scope offset
            size_t hiddenParamIndex = paramIndex - totalRegularParams;
            if (hiddenParamIndex >= currentFunc->hiddenParamsInfo.size()) {
                throw std::runtime_error("Hidden parameter index out of range");
            }
            
            const ParameterInfo& hiddenParam = currentFunc->hiddenParamsInfo[hiddenParamIndex];
            std::cout << "Loading hidden parameter " << hiddenParamIndex << " (total param index " << paramIndex << ") from scope offset " << hiddenParam.offset << " using scope register" << std::endl;
            cb->mov(destReg, x86::ptr(scopeReg, hiddenParam.offset));
        }
    } else {
        // Current scope is a block - only has hidden parameters (parent scope pointers)
        // For blocks, paramIndex directly maps to the index of the parent scope pointer
        std::cout << "Loading parent scope pointer " << paramIndex << " from block scope offset " << (paramIndex * 8) << " using scope register" << std::endl;
        cb->mov(destReg, x86::ptr(scopeReg, paramIndex * 8));
    }
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

void CodeGenerator::loadVariableFromScope(IdentifierNode* identifier, x86::Gp destReg, int offsetInVariable, x86::Gp sourceScopeReg) {
    if (!identifier->varRef) {
        throw std::runtime_error("Variable reference not analyzed: " + identifier->value);
    }
    
    // Get the variable access information
    auto access = identifier->getVariableAccess();
    
    if (access.inCurrentScope) {
        // Variable is in current scope (use provided source scope register)
        std::cout << "Loading variable '" << identifier->value << "' from current scope at offset " << access.offset << " with additional offset " << offsetInVariable << std::endl;
        cb->mov(destReg, x86::ptr(sourceScopeReg, access.offset + offsetInVariable));
    } else {
        // Variable is in a parent scope - load the parent scope pointer from our lexical scope first
        std::cout << "Loading variable '" << identifier->value << "' from parent scope parameter index " << access.scopeParameterIndex << " at offset " << access.offset << " with additional offset " << offsetInVariable << std::endl;
        
        // Load parent scope pointer from our lexical scope into a temporary register
        loadParameterIntoRegister(access.scopeParameterIndex, x86::rax, sourceScopeReg);
        // Now load the variable from that parent scope
        cb->mov(destReg, x86::ptr(x86::rax, access.offset + offsetInVariable));
    }
}

void CodeGenerator::loadVariableAddress(IdentifierNode* identifier, x86::Gp destReg, int offsetInVariable, x86::Gp sourceScopeReg) {
    if (!identifier->varRef) {
        throw std::runtime_error("Variable reference not analyzed: " + identifier->value);
    }
    
    // Get the variable access information
    auto access = identifier->getVariableAccess();
    
    if (access.inCurrentScope) {
        // Variable is in current scope - load address using LEA (use provided source scope register)
        std::cout << "Loading address of variable '" << identifier->value << "' from current scope at offset " << access.offset << " with additional offset " << offsetInVariable << std::endl;
        cb->lea(destReg, x86::ptr(sourceScopeReg, access.offset + offsetInVariable));
    } else {
        // Variable is in a parent scope - load the parent scope pointer from our lexical scope first
        std::cout << "Loading address of variable '" << identifier->value << "' from parent scope parameter index " << access.scopeParameterIndex << " at offset " << access.offset << " with additional offset " << offsetInVariable << std::endl;
        
        // Load parent scope pointer from our lexical scope into a temporary register
        loadParameterIntoRegister(access.scopeParameterIndex, x86::rax, sourceScopeReg);
        // Now load the address from that parent scope
        cb->lea(destReg, x86::ptr(x86::rax, access.offset + offsetInVariable));
    }
}

void CodeGenerator::generatePrintStmt(ASTNode* printStmt) {
    if (printStmt->children.empty()) {
        throw std::runtime_error("Print statement without argument");
    }
    
    ASTNode* arg = printStmt->children[0].get();
    
    DataType detectedType = DataType::INT64;
    if (arg->type == AstNodeType::LITERAL) {
        auto* literal = static_cast<LiteralNode*>(arg);
        detectedType = (literal->literalKind == LiteralType::STRING) ? DataType::STRING : DataType::INT64;
    } else if (arg->type == AstNodeType::IDENTIFIER) {
        auto* identifier = static_cast<IdentifierNode*>(arg);
        if (identifier->varRef) {
            detectedType = identifier->varRef->type;
        }
    } else if (arg->type == AstNodeType::MEMBER_ACCESS) {
        auto* memberAccess = static_cast<MemberAccessNode*>(arg);
        if (memberAccess->classRef) {
            auto it = memberAccess->classRef->fields.find(memberAccess->memberName);
            if (it != memberAccess->classRef->fields.end()) {
                detectedType = it->second.type;
            }
        }
    }
    
    switch (detectedType) {
        case DataType::ANY: {
            if (arg->type == AstNodeType::IDENTIFIER) {
                auto* identifier = static_cast<IdentifierNode*>(arg);
                loadVariableFromScope(identifier, x86::rdi, 0);
                loadVariableFromScope(identifier, x86::rsi, 8);
            } else {
                loadAnyValue(arg, x86::rsi, x86::rdi);
            }
            uint64_t printAddr = reinterpret_cast<uint64_t>(&print_any);
            cb->sub(x86::rsp, 8); // Maintain 16-byte alignment for variadic call
            cb->mov(x86::rax, printAddr);
            cb->call(x86::rax);
            cb->add(x86::rsp, 8);
            break;
        }
        case DataType::FLOAT64: {
            uint64_t bits = 0;
            if (arg->type == AstNodeType::LITERAL) {
                double floatValue = std::stod(static_cast<LiteralNode*>(arg)->value);
                std::memcpy(&bits, &floatValue, sizeof(bits));
                cb->mov(x86::rax, bits);
            } else if (arg->type == AstNodeType::IDENTIFIER) {
                loadVariableFromScope(static_cast<IdentifierNode*>(arg), x86::rax);
            } else if (arg->type == AstNodeType::MEMBER_ACCESS) {
                generateMemberAccess(static_cast<MemberAccessNode*>(arg), x86::rax);
            } else {
                throw std::runtime_error("Unsupported expression for float64 print");
            }
            cb->movq(x86::xmm0, x86::rax);
            uint64_t printAddr = reinterpret_cast<uint64_t>(&print_float64);
            cb->mov(x86::rax, printAddr);
            cb->call(x86::rax);
            break;
        }
        case DataType::STRING: {
            if (arg->type != AstNodeType::LITERAL) {
                throw std::runtime_error("String print currently supports only literals");
            }
            auto* literal = static_cast<LiteralNode*>(arg);
            uint64_t strAddr = reinterpret_cast<uint64_t>(literal->value.c_str());
            cb->mov(x86::rdi, strAddr);
            uint64_t printAddr = reinterpret_cast<uint64_t>(&print_string);
            cb->mov(x86::rax, printAddr);
            cb->call(x86::rax);
            break;
        }
        default: {
            if (arg->type == AstNodeType::IDENTIFIER) {
                loadVariableFromScope(static_cast<IdentifierNode*>(arg), x86::rdi);
            } else {
                loadValue(arg, x86::rdi);
            }
            uint64_t printAddr = reinterpret_cast<uint64_t>(&print_int64);
            cb->mov(x86::rax, printAddr);
            cb->call(x86::rax);
            break;
        }
    }
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

void CodeGenerator::patchMetadataClosures(void* codeBase, const std::map<std::string, ClassDeclNode*>& classRegistry) {
    std::cout << "\n=== Patching Metadata Closures ===" << std::endl;
    
    // Iterate through all classes and patch their method closures
    for (const auto& [className, classDecl] : classRegistry) {
        ClassMetadata* metadata = MetadataRegistry::getInstance().getClassMetadata(className);
        if (!metadata) {
            std::cout << "WARNING: No metadata found for class " << className << std::endl;
            continue;
        }
        
        std::cout << "Patching " << metadata->numMethods << " methods for class " << className << std::endl;
        
        // Patch each method closure
        for (size_t i = 0; i < classDecl->methodLayout.size(); i++) {
            const auto& methodInfo = classDecl->methodLayout[i];
            FunctionDeclNode* method = methodInfo.method;
            
            if (!method || !method->asmjitLabel) {
                std::cout << "WARNING: No label for method " << methodInfo.methodName << std::endl;
                continue;
            }
            
            // Get the label and resolve its offset
            Label* label = static_cast<Label*>(method->asmjitLabel);
            uint32_t labelId = label->id();
            
            if (labelId == Globals::kInvalidId) {
                throw std::runtime_error("Invalid label ID for method: " + methodInfo.methodName);
            }
            
            LabelEntry* labelEntry = code.labelEntry(labelId);
            if (!labelEntry) {
                throw std::runtime_error("Label entry not found for method: " + methodInfo.methodName);
            }
            
            size_t labelOffset = labelEntry->offset();
            void* funcAddr = reinterpret_cast<void*>(reinterpret_cast<uint8_t*>(codeBase) + labelOffset);
            
            // Patch the closure in metadata
            Closure* closure = metadata->methodClosures[i];
            closure->funcAddr = funcAddr;
            
            std::cout << "  Patched " << className << "::" << methodInfo.methodName 
                      << " -> " << funcAddr << " (offset: 0x" << std::hex << labelOffset << std::dec << ")" << std::endl;
        }
    }
    
    std::cout << "=== Patching Complete ===" << std::endl;
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
    
    // Preserve callee-saved registers we use for scope management
    cb->push(x86::r14);
    cb->push(x86::r15);
    
    // Special case: main function needs to allocate its own scope since it's not called via our convention
    if (funcDecl->funcName == "main") {
        std::cout << "Main function - allocating scope in prologue" << std::endl;
        
        // Initialize r14 and r15 to nullptr for main (no parent scope)
        cb->xor_(x86::r14, x86::r14);
        cb->xor_(x86::r15, x86::r15);
        
        // Allocate scope for main
        allocateScope(funcDecl);
        
        // Main has no parameters, so nothing to copy
        std::cout << "Main scope allocated" << std::endl;
    } else {
        // NOTE: For regular functions, scope allocation and parameter copying now happens at the call site!
        // The function receives r15 already pointing to an allocated scope with parameters populated.
        // r14 points to the parent scope.
        // We don't need to save any registers or copy parameters here.
        
        std::cout << "Function prologue complete - scope already allocated by caller" << std::endl;
    }
}

void CodeGenerator::generateFunctionEpilogue(FunctionDeclNode* funcDecl) {
    std::cout << "Generating epilogue for function: " << funcDecl->funcName << std::endl;
    
    // Use generic scope epilogue to free scope and restore parent scope pointer
    generateScopeEpilogue(funcDecl);
    
    // Restore preserved callee-saved registers
    cb->pop(x86::r15);
    cb->pop(x86::r14);
    
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
    
    // Store the closure size (in bytes) right after the function address
    size_t closureSize = it->second.size;
    cb->mov(x86::rax, closureSize);
    cb->mov(x86::ptr(x86::r15, offset + 8), x86::rax);

    // now store any needed closure addresses for parent scopes allNeeded
    // loop through allNeeded with index to calculate proper offset
    int scopeIndex = 0;
    for (const auto& neededDepth : funcDecl->allNeeded) {
        int scopeOffset = offset + 16 + (scopeIndex * 8); // function_address (8) + size (8) + scope_pointers
        bool handled = false;

        // Special case: if we're in the scope that matches the needed depth,
        // we don't need to look up parameter mapping - use current scope directly
        if (scope->depth == neededDepth) {
            cb->mov(x86::rax, x86::r15); // current scope address
            handled = true;
        } else {
            // find parameter index in scopeDepthToParentParameterIndexMap
            auto mapIt = scope->scopeDepthToParentParameterIndexMap.find(neededDepth);
            if (mapIt == scope->scopeDepthToParentParameterIndexMap.end()) {
                throw std::runtime_error("Needed variable not found in scope: " + std::to_string(neededDepth));
            }

            int paramIndex = mapIt->second;
            if (paramIndex == -1) {
                // Immediate parent scope lives in r14
                cb->mov(x86::rax, x86::r14);
                handled = true;
            } else if (auto funcDeclParent = dynamic_cast<FunctionDeclNode*>(scope)) {
                // Function scope: parent pointers are stored in hidden parameters
                int hiddenParamIndex = paramIndex - static_cast<int>(funcDeclParent->paramsInfo.size());
                if (hiddenParamIndex < 0 || hiddenParamIndex >= static_cast<int>(funcDeclParent->hiddenParamsInfo.size())) {
                    throw std::runtime_error("Hidden parameter index out of range for needed variable: " + std::to_string(neededDepth));
                }
                int hiddenParamOffset = funcDeclParent->hiddenParamsInfo[hiddenParamIndex].offset;
                cb->mov(x86::rax, x86::ptr(x86::r15, hiddenParamOffset)); // load parent scope address from current scope's parameters
                handled = true;
            } else {
                // Block scope: parent pointers are stored sequentially after metadata
                int blockIndex = -1;
                for (size_t i = 0; i < scope->allNeeded.size(); ++i) {
                    if (scope->allNeeded[i] == neededDepth) {
                        blockIndex = static_cast<int>(i);
                        break;
                    }
                }
                if (blockIndex < 0) {
                    throw std::runtime_error("Block scope missing needed depth: " + std::to_string(neededDepth));
                }
                int parentPtrOffset = 8 + (blockIndex * 8);
                cb->mov(x86::rax, x86::ptr(x86::r15, parentPtrOffset));
                handled = true;
            }
        }

        if (!handled) {
            throw std::runtime_error("Failed to resolve scope pointer for closure: " + funcDecl->funcName);
        }

        cb->mov(x86::ptr(x86::r15, scopeOffset), x86::rax); // store in closure at proper offset
        scopeIndex++;
    }
}

// Generic scope management utilities that can be shared by functions and blocks
void CodeGenerator::generateScopePrologue(LexicalScopeNode* scope) {
    std::cout << "Generating scope prologue for scope at depth: " << scope->depth << std::endl;
    
    // Check if this is a function scope - functions are now handled at call site!
    if (dynamic_cast<FunctionDeclNode*>(scope)) {
        throw std::runtime_error("Function scopes should not use generateScopePrologue - scope allocated at call site!");
    }
    
    // This is a block scope - allocate and set up as before
    // Allocate the new scope (this will set r15 to point to the new scope)
    allocateScope(scope);
    
    // Copy needed parent scope addresses from current lexical environment
    std::cout << "Setting up block scope with access to " << scope->allNeeded.size() << " parent scopes" << std::endl;
    
    // For each needed parent scope depth, we need to find where to get the scope address from
    int scopeIndex = 0;
    for (const auto& neededDepth : scope->allNeeded) {
        // Calculate offset in the new scope where this parent scope address should be stored
        auto it = scope->scopeDepthToParentParameterIndexMap.find(neededDepth);
        if (it == scope->scopeDepthToParentParameterIndexMap.end()) {
            throw std::runtime_error("Needed parent scope not found in parameter mapping: " + std::to_string(neededDepth));
        }
        
        int paramIndex = it->second;
        // For blocks, we use a simple offset calculation since we don't have real parameters
        // Start at offset 8 to skip the flags field
        int offset = 8 + (scopeIndex * 8);
        
        std::cout << "  Parent scope at depth " << neededDepth << " -> block scope[" << offset << "]" << std::endl;

        std::cout << "    (paramIndex = " << paramIndex << ")" << std::endl;
        
        if (paramIndex == -1) {
            // Parent scope is current r14 (saved parent scope)
            cb->mov(x86::ptr(x86::r15, offset), x86::r14);
        } else {
            // Parent scope is stored in the current scope as a hidden parameter
            // Load it from the parent scope (r14) using proper parameter loading
            loadParameterIntoRegister(paramIndex, x86::rax, x86::r14);
            cb->mov(x86::ptr(x86::r15, offset), x86::rax); // Store in new scope
        }
        
        scopeIndex++;
    }

    // Create closures for any nested functions declared in this block scope
    for (const auto& [name, varInfo] : scope->variables) {
        if (varInfo.type == DataType::CLOSURE && varInfo.funcNode) {
            storeFunctionAddressInClosure(varInfo.funcNode, scope);
        }
    }
}

void CodeGenerator::generateScopeEpilogue(LexicalScopeNode* scope) {
    std::cout << "Generating scope epilogue for scope at depth: " << scope->depth << std::endl;
    
    // Pop scope from GC roots - this removes it from the active scope stack
    // but does NOT free the memory. The GC will handle scope destruction later.
    uint64_t gcPopScopeAddr = reinterpret_cast<uint64_t>(&gc_pop_scope);
    cb->mov(x86::rax, gcPopScopeAddr);
    cb->call(x86::rax);
    
    // DO NOT call free() here! Scopes should only be destroyed by the garbage collector.
    // The scope is now out of scope (removed from GC roots) but the memory remains
    // until the GC determines it's safe to free.
    
    // Restore r15 to the parent scope (from r14)
    cb->mov(x86::r15, x86::r14);
    
    // Restore r14 from the stack (the old parent)
    cb->pop(x86::r14);
}

void CodeGenerator::generateBlockStmt(BlockStmtNode* blockStmt) {
    std::cout << "Generating block statement" << std::endl;
    
    // Generate the scope prologue (allocate new scope, copy parent scope addresses)
    generateScopePrologue(blockStmt);
    
    // Update current scope for variable resolution
    LexicalScopeNode* prevScope = currentScope;
    currentScope = blockStmt;
    
    // Generate code for all statements in the block
    for (auto& child : blockStmt->children) {
        visitNode(child.get());
    }
    
    // Restore previous scope
    currentScope = prevScope;
    
    // Generate the scope epilogue (free scope, restore parent scope pointer)
    generateScopeEpilogue(blockStmt);
}

void CodeGenerator::generateFunctionCall(FunctionCallNode* funcCall) {
    std::cout << "Generating function call: " << funcCall->value << std::endl;
    
    // Check if this is actually a method call
    MethodCallNode* methodCall = dynamic_cast<MethodCallNode*>(funcCall);
    bool isMethodCall = (methodCall != nullptr);
    
    if (isMethodCall) {
        std::cout << "  -> This is a method call on object" << std::endl;
    }
    
    // Get target function information
    FunctionDeclNode* targetFunc;
    
    if (isMethodCall) {
        targetFunc = methodCall->resolvedMethod;
    } else {
        targetFunc = funcCall->varRef->funcNode;
    }
    
    if (!targetFunc) {
        throw std::runtime_error("Cannot resolve target function for call: " + funcCall->value);
    }
    
    std::cout << "Target function has " << targetFunc->paramsInfo.size() << " regular params and " 
              << targetFunc->hiddenParamsInfo.size() << " hidden params" << std::endl;
    
    // Allocate scope for the callee
    // This will:
    // - Push r14 (save grandparent scope)
    // - Set r14 = r15 (current scope becomes parent of new scope)
    // - Allocate new scope memory
    // - Set r15 = new scope
    allocateScope(targetFunc);
    
    // Now r15 points to the new (child) scope, r14 points to caller's scope
    // We need to copy parameters from r14 (caller scope) to r15 (child scope)
    
    // Copy regular parameters into the child scope
    if (isMethodCall) {
        // First parameter is "this"
        const VariableInfo& thisParam = targetFunc->paramsInfo[0];
        std::cout << "  Copying 'this' to scope[" << thisParam.offset << "]" << std::endl;
        loadValue(methodCall->object.get(), x86::rax, x86::r14, DataType::OBJECT);
        cb->mov(x86::ptr(x86::r15, thisParam.offset), x86::rax);
        
        // Then copy explicit method arguments
        for (size_t i = 0; i < methodCall->args.size(); i++) {
            const VariableInfo& param = targetFunc->paramsInfo[i + 1];
            ASTNode* arg = methodCall->args[i].get();
            
            std::cout << "  Copying method arg " << (i + 1) << " to scope[" << param.offset << "]" << std::endl;
            
            if (arg->type == AstNodeType::IDENTIFIER) {
                // Load from caller's scope (r14) 
                loadVariableFromScope(static_cast<IdentifierNode*>(arg), x86::rax, 0, x86::r14);
            } else {
                loadValue(arg, x86::rax, x86::r14, param.type);
            }
            cb->mov(x86::ptr(x86::r15, param.offset), x86::rax);
        }
    } else {
        // Regular function call - copy all arguments
        for (size_t i = 0; i < funcCall->args.size(); i++) {
            const VariableInfo& param = targetFunc->paramsInfo[i];
            ASTNode* arg = funcCall->args[i].get();
            
            std::cout << "  Copying regular arg " << i << " (" << param.name << ") to scope[" << param.offset << "]" << std::endl;
            
            if (arg->type == AstNodeType::IDENTIFIER) {
                // Load from caller's scope (r14)
                loadVariableFromScope(static_cast<IdentifierNode*>(arg), x86::rax, 0, x86::r14);
            } else {
                loadValue(arg, x86::rax, x86::r14, param.type);
            }
            cb->mov(x86::ptr(x86::r15, param.offset), x86::rax);
        }
    }
    
    // Load the closure address for accessing hidden parameters (parent scope pointers)
    // For method calls, load from object; for regular calls, load from variable
    if (isMethodCall) {
        // Load object pointer into rbx
        loadValue(methodCall->object.get(), x86::rbx, x86::r14, DataType::OBJECT);
        // Add offset to get to the method closure pointer in the object
        int closurePtrOffset = ObjectLayout::HEADER_SIZE + methodCall->methodClosureOffset;
        std::cout << "  Loading method closure pointer from object at offset " << closurePtrOffset << std::endl;
        // Load the closure pointer (not add offset to object, but load the pointer value)
        cb->mov(x86::rbx, x86::qword_ptr(x86::rbx, closurePtrOffset));
    } else {
        // Load closure address from caller's scope (r14)
        loadVariableAddress(static_cast<IdentifierNode*>(funcCall), x86::rbx, 0, x86::r14);
    }
    
    // Copy hidden parameters (parent scope pointers) from closure into child scope
    for (size_t i = 0; i < targetFunc->hiddenParamsInfo.size(); i++) {
        const ParameterInfo& hiddenParam = targetFunc->hiddenParamsInfo[i];
        int closureOffset = 16 + (i * 8); // function_address (8) + size (8) + scope_pointers
        
        std::cout << "  Copying hidden param " << i << " (depth " << hiddenParam.depth 
                  << ") to scope[" << hiddenParam.offset << "]" << std::endl;
        
        // Load the scope pointer from closure and store in child scope
        cb->mov(x86::rax, x86::ptr(x86::rbx, closureOffset));
        cb->mov(x86::ptr(x86::r15, hiddenParam.offset), x86::rax);
    }
    
    // Load the function address from closure
    // For both method and regular calls, rbx points to the closure
    // Closure layout: [size(8)][func_addr(8)][scope_ptr1(8)]...[scope_ptrN(8)]
    cb->mov(x86::rax, x86::ptr(x86::rbx, 8)); // Load function address from closure (offset 8, after size)
    
    // Make the call - r15 already points to the pre-allocated and populated scope
    // The callee will use this scope directly
    cb->call(x86::rax);
    
    // After call returns, the callee's epilogue has already:
    // - Freed its scope (called gc_pop_scope)
    // - Done: mov r15, r14 (restored parent scope, which is our scope)
    // - Done: pop r14 (restored grandparent scope pointer)
    // So now r15 points back to our scope and r14 is restored
    
    std::cout << "Function call complete" << std::endl;
}

void CodeGenerator::generateGoStmt(GoStmtNode* goStmt) {
    std::cout << "Generating GO statement for function: " << goStmt->functionCall->value << std::endl;
    
    FunctionCallNode* funcCall = goStmt->functionCall.get();
    
    // Find the target function
    if (!funcCall->varRef) {
        throw std::runtime_error("Function not found in go statement: " + funcCall->value);
    }
    
    if (funcCall->varRef->type != DataType::CLOSURE) {
        throw std::runtime_error("Go statement target is not a function: " + funcCall->value);
    }
    
    FunctionDeclNode* targetFunc = funcCall->varRef->funcNode;
    if (!targetFunc) {
        throw std::runtime_error("Cannot resolve target function for go statement: " + funcCall->value);
    }
    
    std::cout << "Target function has " << targetFunc->paramsInfo.size() << " regular params and " 
              << targetFunc->hiddenParamsInfo.size() << " hidden params" << std::endl;
    
    // Save current r15 (our scope) into r13 temporarily - we'll need it for loading arguments
    cb->mov(x86::r13, x86::r15);
    
    // Allocate scope for the goroutine function (same as regular function call)
    // This will:
    // - Push r14 (save grandparent scope)
    // - Set r14 = r15 (current scope becomes parent of new scope)
    // - Allocate new scope memory
    // - Set r15 = new scope
    allocateScope(targetFunc);
    
    // Now r15 points to the new scope, r14 points to our scope (r13 also has our scope)
    // Copy regular parameters into the goroutine's scope
    for (size_t i = 0; i < funcCall->args.size(); i++) {
        const VariableInfo& param = targetFunc->paramsInfo[i];
        ASTNode* arg = funcCall->args[i].get();
        
        std::cout << "  Copying arg " << i << " (" << param.name << ") to scope[" << param.offset << "]" << std::endl;
        
        if (arg->type == AstNodeType::IDENTIFIER) {
            // Load from our scope (r13 has our original scope)
            loadVariableFromScope(static_cast<IdentifierNode*>(arg), x86::rax, 0, x86::r13);
        } else {
            loadValue(arg, x86::rax, x86::r13, param.type);
        }
        cb->mov(x86::ptr(x86::r15, param.offset), x86::rax);
    }
    
    // Load the closure address for accessing hidden parameters (parent scope pointers)
    loadVariableAddress(funcCall, x86::rbx, 0, x86::r13);
    
    // Copy hidden parameters (parent scope pointers) from closure into goroutine's scope
    for (size_t i = 0; i < targetFunc->hiddenParamsInfo.size(); i++) {
        const ParameterInfo& hiddenParam = targetFunc->hiddenParamsInfo[i];
        int closureOffset = 16 + (i * 8); // function_address (8) + size (8) + scope_pointers
        
        std::cout << "  Copying hidden param " << i << " (depth " << hiddenParam.depth 
                  << ") to scope[" << hiddenParam.offset << "]" << std::endl;
        
        // Load the scope pointer from closure and store in goroutine's scope
        cb->mov(x86::rax, x86::ptr(x86::rbx, closureOffset));
        cb->mov(x86::ptr(x86::r15, hiddenParam.offset), x86::rax);
    }
    
    // Load the function address from closure (still in rbx)
    // Closure layout: [size(8)][func_addr(8)][scope_ptr1(8)]...[scope_ptrN(8)]
    cb->mov(x86::rax, x86::ptr(x86::rbx, 8)); // Load function address from closure (offset 8, after size)
    
    // Now we have:
    // - rax = function pointer to call
    // - r15 = pointer to allocated scope with all parameters populated
    // - r14 = pointer to parent scope (our scope)
    
    // We need to pass these to runtime_spawn_goroutine
    // Signature: void runtime_spawn_goroutine(void* funcPtr, void* scopePtr, void* parentScopePtr)
    cb->mov(x86::rdi, x86::rax);  // First arg: function pointer
    cb->mov(x86::rsi, x86::r15);  // Second arg: scope pointer
    cb->mov(x86::rdx, x86::r14);  // Third arg: parent scope pointer
    
    // Save our scope register r13 before calling runtime function
    cb->push(x86::r13);
    
    // Call runtime_spawn_goroutine
    uint64_t runtimeAddr = reinterpret_cast<uint64_t>(&runtime_spawn_goroutine);
    cb->mov(x86::rax, runtimeAddr);
    cb->call(x86::rax);
    
    // Restore our scope register
    cb->pop(x86::r13);
    
    // Restore r15 and r14 to their original state (before we allocated the goroutine's scope)
    // The goroutine now owns the allocated scope, so we need to restore our state
    cb->mov(x86::r15, x86::r13);  // Restore our scope to r15
    cb->pop(x86::r14);            // Restore grandparent scope pointer
    
    std::cout << "Generated GO statement - scope allocated and ownership transferred to goroutine" << std::endl;
}

void CodeGenerator::generateSetTimeoutStmt(SetTimeoutStmtNode* setTimeoutStmt) {
    std::cout << "Generating setTimeout statement for function: " << setTimeoutStmt->functionName->value << std::endl;
    
    // Find the target function
    if (!setTimeoutStmt->functionName->varRef) {
        throw std::runtime_error("Function not found in setTimeout statement: " + setTimeoutStmt->functionName->value);
    }
    
    if (setTimeoutStmt->functionName->varRef->type != DataType::CLOSURE) {
        throw std::runtime_error("setTimeout target is not a function: " + setTimeoutStmt->functionName->value);
    }
    
    // Get the function address from the closure
    // Similar to generateGoStmt but with additional delay parameter
    x86::Gp funcPtrReg = x86::rdi;  // First argument to runtime_set_timeout
    loadVariableAddress(setTimeoutStmt->functionName.get(), funcPtrReg, 0); // Load closure address
    cb->mov(funcPtrReg, x86::qword_ptr(funcPtrReg)); // Dereference to get function pointer
    
    // For now, pass NULL for args and 0 for argsSize (no argument support yet)
    cb->mov(x86::rsi, 0);  // args = NULL  
    cb->mov(x86::rdx, 0);  // argsSize = 0
    
    // Fourth argument: delay in milliseconds (parse from literal)
    int delayMs = std::stoi(setTimeoutStmt->delay->value);
    cb->mov(x86::rcx, delayMs);  // delayMs
    
    // Save registers before calling runtime function
    cb->push(x86::rax);
    cb->push(x86::r8);
    cb->push(x86::r9);
    cb->push(x86::r10);
    cb->push(x86::r11);
    
    // Call runtime_set_timeout(func, args, argsSize, delayMs)
    uint64_t runtimeAddr = reinterpret_cast<uint64_t>(&runtime_set_timeout);
    cb->mov(x86::rax, runtimeAddr);
    cb->call(x86::rax);
    
    // Restore registers
    cb->pop(x86::r11);
    cb->pop(x86::r10);
    cb->pop(x86::r9);
    cb->pop(x86::r8);
    cb->pop(x86::rax);
    
    std::cout << "Generated setTimeout statement call to runtime_set_timeout" << std::endl;
}

void CodeGenerator::generateAwaitExpr(ASTNode* awaitExpr, x86::Gp destReg) {
    std::cout << "Generating await expression" << std::endl;
    
    // The await expression should have a child (sleep call)
    if (awaitExpr->children.empty()) {
        throw std::runtime_error("Await expression has no children");
    }
    
    // Generate the async operation (e.g., sleep call)
    ASTNode* asyncOp = awaitExpr->children[0].get();
    generateSleepCall(asyncOp, x86::rdi); // Put promise ID directly in rdi (first argument register)
    
    
    // Call runtime_await_promise(promiseId) - promise ID is already in rdi
    uint64_t runtimeAddr = reinterpret_cast<uint64_t>(&runtime_await_promise);
    cb->mov(x86::rax, runtimeAddr);
    cb->call(x86::rax);
    
    // Result (resolved value) is in rax, move to destReg if different
    if (destReg.id() != x86::rax.id()) {
        cb->mov(destReg, x86::rax);
    }
    
    std::cout << "Generated await expression - promise awaited" << std::endl;
}

void CodeGenerator::generateSleepCall(ASTNode* sleepCall, x86::Gp destReg) {
    std::cout << "Generating sleep call" << std::endl;
    
    // The sleep call should have a child (the duration literal)
    if (sleepCall->children.empty()) {
        throw std::runtime_error("Sleep call has no duration argument");
    }
    
    // Load the sleep duration from the literal
    ASTNode* durationNode = sleepCall->children[0].get();
    if (durationNode->type != AstNodeType::LITERAL) {
        throw std::runtime_error("Sleep duration must be a literal");
    }
    
    int64_t duration = std::stoll(durationNode->value);
    cb->mov(x86::rdi, duration); // First argument: duration in milliseconds
    
    // Save registers before calling runtime function (don't save rax since it will have the return value)
    cb->push(x86::rcx);
    cb->push(x86::r8);
    cb->push(x86::r9);
    cb->push(x86::r10);
    cb->push(x86::r11);
    
    // Call runtime_sleep(milliseconds)
    uint64_t runtimeAddr = reinterpret_cast<uint64_t>(&runtime_sleep);
    cb->mov(x86::rax, runtimeAddr);
    cb->call(x86::rax);
    
    // Restore registers (don't restore rax since it contains the return value)
    cb->pop(x86::r11);
    cb->pop(x86::r10);
    cb->pop(x86::r9);
    cb->pop(x86::r8);
    cb->pop(x86::rcx);
    
    // Result (promise ID) is in rax, move to destReg if different
    if (destReg.id() != x86::rax.id()) {
        cb->mov(destReg, x86::rax);
    }
    
    std::cout << "Generated sleep call - promise ID returned" << std::endl;
}

void CodeGenerator::generateNewExpr(NewExprNode* newExpr, x86::Gp destReg) {
    std::cout << "Generating new expression for class: " << newExpr->className << std::endl;
    
    // Verify that the class reference was set during analysis
    if (!newExpr->classRef) {
        throw std::runtime_error("Class reference not set for new expression: " + newExpr->className);
    }
    
    ClassDeclNode* classDecl = newExpr->classRef;
    
    // Calculate total object size: header + packed fields (includes closure pointers + regular fields)
    int totalObjectSize = ObjectLayout::HEADER_SIZE + classDecl->totalSize;
    
    std::cout << "DEBUG generateNewExpr: Allocating object of size " << totalObjectSize 
              << " (header=" << ObjectLayout::HEADER_SIZE 
              << ", packed fields=" << classDecl->totalSize << ")" << std::endl;
    
    // Call calloc to allocate and zero-initialize object
    // mov rdi, 1 (number of elements)
    cb->mov(x86::rdi, 1);
    // mov rsi, totalObjectSize (size of each element)
    cb->mov(x86::rsi, totalObjectSize);
    
    // Call calloc
    uint64_t callocAddr = reinterpret_cast<uint64_t>(&calloc_wrapper);
    cb->mov(x86::rax, callocAddr);
    cb->call(x86::rax);
    
    // Object pointer is now in rax
    // We need to initialize the object header
    
    // Get class metadata from registry and store at offset 0
    ClassMetadata* metadata = MetadataRegistry::getInstance().getClassMetadata(classDecl->className);
    if (!metadata) {
        throw std::runtime_error("Class metadata not found for: " + classDecl->className);
    }
    uint64_t metadataAddr = reinterpret_cast<uint64_t>(metadata);
    cb->mov(x86::r10, metadataAddr);
    cb->mov(x86::qword_ptr(x86::rax, ObjectLayout::METADATA_OFFSET), x86::r10);
    
    // Store flags at offset 8 (currently 0, zero-initialized by calloc)
    // cb->mov(x86::qword_ptr(x86::rax, ObjectLayout::FLAGS_OFFSET), 0);  // Not needed, calloc already zeroed
    
    // Initialize closure pointers in the object
    // Set closure pointers using the packed offsets
    for (size_t i = 0; i < classDecl->methodLayout.size(); i++) {
        const auto& methodInfo = classDecl->methodLayout[i];
        int closurePtrOffset = ObjectLayout::HEADER_SIZE + methodInfo.closureOffsetInObject;
        
        std::cout << "DEBUG generateNewExpr: Setting closure pointer " << i 
                  << " ('" << methodInfo.methodName << "') at object offset " << closurePtrOffset << std::endl;
        
        // Get the closure from metadata's simple array
        Closure* metadataClosure = metadata->methodClosures[i];
        if (!metadataClosure) {
            throw std::runtime_error("Failed to get closure for method: " + methodInfo.methodName);
        }
        
        uint64_t closureAddr = reinterpret_cast<uint64_t>(metadataClosure);
        
        // Store the closure pointer in the object
        cb->push(x86::rax); // Save object pointer
        cb->mov(x86::r10, closureAddr);
        cb->mov(x86::qword_ptr(x86::rax, closurePtrOffset), x86::r10);
        cb->pop(x86::rax); // Restore object pointer
    }
    
    std::cout << "DEBUG generateNewExpr: Object allocated at runtime, class metadata stored at offset " 
              << ObjectLayout::METADATA_OFFSET << std::endl;
    
    // Track object in GC (save rax first since it contains the object pointer)
    cb->push(x86::rax);
    cb->mov(x86::rdi, x86::rax);  // First argument: object pointer
    uint64_t gcTrackAddr = reinterpret_cast<uint64_t>(&gc_track_object);
    cb->mov(x86::r11, gcTrackAddr);
    cb->call(x86::r11);
    cb->pop(x86::rax);  // Restore object pointer
    
    // Move result to destination register if different
    if (destReg.id() != x86::rax.id()) {
        cb->mov(destReg, x86::rax);
    }
    
    std::cout << "Generated new expression - object pointer returned" << std::endl;
}

void CodeGenerator::generateMemberAccess(MemberAccessNode* memberAccess, x86::Gp destReg) {
    std::cout << "Generating member access for member: " << memberAccess->memberName << std::endl;
    
    // Verify that the class reference and member offset were set during analysis
    if (!memberAccess->classRef) {
        throw std::runtime_error("Class reference not set for member access: " + memberAccess->memberName);
    }
    
    std::cout << "DEBUG generateMemberAccess: Accessing member '" << memberAccess->memberName 
              << "' at offset " << memberAccess->memberOffset << " in class '" 
              << memberAccess->classRef->className << "'" << std::endl;
    
    // Load the object pointer into a temporary register
    // The object could be an identifier (variable) or another expression
    x86::Gp objectPtrReg = x86::r10;
    loadValue(memberAccess->object.get(), objectPtrReg);
    
    // Use the pre-calculated absolute offset (already includes header)
    int actualOffset = memberAccess->memberOffset;
    
    std::cout << "DEBUG generateMemberAccess: Loading from object pointer + " << actualOffset 
              << " (absolute offset)" << std::endl;
    
    // Load the field value from [objectPtrReg + actualOffset] into destReg
    cb->mov(destReg, x86::qword_ptr(objectPtrReg, actualOffset));
    
    std::cout << "Generated member access - field value loaded" << std::endl;
}

void CodeGenerator::generateMemberAssign(MemberAssignNode* memberAssign) {
    std::cout << "Generating member assignment" << std::endl;
    
    if (!memberAssign->member) {
        throw std::runtime_error("Member assignment has no member access node");
    }
    
    MemberAccessNode* member = memberAssign->member.get();
    
    // Verify that the class reference and member offset were set during analysis
    if (!member->classRef) {
        throw std::runtime_error("Class reference not set for member assignment: " + member->memberName);
    }
    
    std::cout << "DEBUG generateMemberAssign: Assigning to member '" << member->memberName 
              << "' at offset " << member->memberOffset << " in class '" 
              << member->classRef->className << "'" << std::endl;
    
    // Load the object pointer into a temporary register
    x86::Gp objectPtrReg = x86::r10;
    loadValue(member->object.get(), objectPtrReg);
    
    DataType fieldType = DataType::INT64;
    auto fieldIt = member->classRef->fields.find(member->memberName);
    if (fieldIt != member->classRef->fields.end()) {
        fieldType = fieldIt->second.type;
    }
    
    // Use the pre-calculated absolute offset (already includes header)
    int actualOffset = member->memberOffset;
    
    if (fieldType == DataType::ANY) {
        loadAnyValue(memberAssign->value.get(), x86::rax, x86::rdx);
        cb->mov(x86::qword_ptr(objectPtrReg, actualOffset), x86::rdx);
        cb->mov(x86::qword_ptr(objectPtrReg, actualOffset + 8), x86::rax);
        
        if (memberAssign->value->type != AstNodeType::NEW_EXPR) {
            Label skipObjectBarrier = cb->newLabel();
            cb->cmp(x86::rdx, static_cast<uint32_t>(DataType::OBJECT));
            cb->jne(skipObjectBarrier);
            
            cb->mov(x86::rcx, x86::qword_ptr(x86::rax, ObjectLayout::FLAGS_OFFSET));
            cb->test(x86::rcx, ObjectFlags::NEEDS_SET_FLAG);
            
            Label skipWriteBarrier = cb->newLabel();
            cb->jz(skipWriteBarrier);
            
            cb->or_(x86::qword_ptr(x86::rax, ObjectLayout::FLAGS_OFFSET), ObjectFlags::SET_FLAG);
            cb->mfence();
            
            cb->bind(skipWriteBarrier);
            cb->bind(skipObjectBarrier);
        }
        
        std::cout << "Generated member assignment for ANY field" << std::endl;
        return;
    }
    
    // Load the value to assign into another register
    x86::Gp valueReg = x86::rax;
    loadValue(memberAssign->value.get(), valueReg, x86::r15, fieldType);
    
    std::cout << "DEBUG generateMemberAssign: Storing to object pointer + " << actualOffset 
              << " (absolute offset)" << std::endl;
    
    // Store the value to [objectPtrReg + actualOffset]
    cb->mov(x86::qword_ptr(objectPtrReg, actualOffset), valueReg);
    
    // Check if we're assigning an object reference
    // We need to check the field type in the class definition
    if (member->classRef) {
        auto it = member->classRef->fields.find(member->memberName);
        if (it != member->classRef->fields.end() && it->second.type == DataType::OBJECT) {
            // Skip write barrier for NEW expressions - they can't be suspected dead yet
            if (memberAssign->value->type != AstNodeType::NEW_EXPR) {
                // Inline GC write barrier - check needs_set_flag and atomically set set_flag if needed
                // This is much faster than a function call
                
                // Load flags from object header (at offset 8)
                // flags is at [valueReg + 8]
                cb->mov(x86::rcx, x86::qword_ptr(valueReg, ObjectLayout::FLAGS_OFFSET));  // Load flags
                
                // Test if NEEDS_SET_FLAG (bit 0) is set
                cb->test(x86::rcx, ObjectFlags::NEEDS_SET_FLAG);
                
                // Create a label for skipping if not needed
                Label skipWriteBarrier = cb->newLabel();
                cb->jz(skipWriteBarrier);  // Jump if zero (NEEDS_SET_FLAG not set)
                
                // NEEDS_SET_FLAG is set, so OR the SET_FLAG bit (no LOCK needed - idempotent)
                // Using non-locked OR is safe because we're only setting a bit to 1
                cb->or_(x86::qword_ptr(valueReg, ObjectLayout::FLAGS_OFFSET), ObjectFlags::SET_FLAG);
                
                // Memory fence to ensure write visibility to GC thread
                // This guarantees the set_flag write is visible before GC reads it in phase 3
                cb->mfence();
                
                cb->bind(skipWriteBarrier);
            }
        }
    }
    
    std::cout << "Generated member assignment - field value stored" << std::endl;
}

void CodeGenerator::generateClassDecl(ClassDeclNode* classDecl) {
    std::cout << "Generating class declaration (inline closure creation): " << classDecl->className << std::endl;
    
    // Get the runtime metadata for this class
    ClassMetadata* metadata = MetadataRegistry::getInstance().getClassMetadata(classDecl->className);
    if (!metadata) {
        throw std::runtime_error("Class metadata not found for: " + classDecl->className);
    }
    
    // The method code should already be generated from the function registry
    // Here we just need to ensure the metadata closures are set up
    // The actual patching of function addresses happens in patchMetadataClosures after code commit
    
    std::cout << "Class " << classDecl->className << " has " << classDecl->methodLayout.size() 
              << " methods (code already generated, closures will be patched)" << std::endl;
    
    for (size_t i = 0; i < classDecl->methodLayout.size(); i++) {
        auto& methodInfo = classDecl->methodLayout[i];
        auto& method = methodInfo.method;
        
        std::cout << "  Method: " << methodInfo.methodName << " - closure will be patched later" << std::endl;
        
        // Verify the label exists
        Label* funcLabel = static_cast<Label*>(method->asmjitLabel);
        if (!funcLabel) {
            throw std::runtime_error("Method label not created for: " + methodInfo.methodName);
        }
        
        // The closure is already in the metadata, it will be patched after code commit
        Closure* closure = metadata->methodClosures[i];
        if (!closure) {
            throw std::runtime_error("Method closure not found in metadata for: " + methodInfo.methodName);
        }
    }
    
    std::cout << "Class declaration processing complete for: " << classDecl->className << std::endl;
}

// Assembly library wrapper methods for internal use
void CodeGenerator::makeSafeUnorderedList(x86::Gp addressReg, x86::Gp offsetReg, int32_t initialSize) {
    if (asmLibrary) {
        asmLibrary->makeSafeUnorderedList(addressReg, offsetReg, initialSize);
    }
}

void CodeGenerator::addToSafeList(x86::Gp addressReg, x86::Gp offsetReg, x86::Gp valueReg) {
    if (asmLibrary) {
        asmLibrary->addToSafeList(addressReg, offsetReg, valueReg);
    }
}

void CodeGenerator::removeFromSafeList(x86::Gp addressReg, x86::Gp offsetReg, x86::Gp indexReg) {
    if (asmLibrary) {
        asmLibrary->removeFromSafeList(addressReg, offsetReg, indexReg);
    }
}

void CodeGenerator::compactSafeList(x86::Gp addressReg, x86::Gp offsetReg) {
    if (asmLibrary) {
        asmLibrary->compactSafeList(addressReg, offsetReg);
    }
}
