#pragma once

#include "ast.h"
#include "library.h"
#include <asmjit/asmjit.h>
#include <capstone/capstone.h>
#include <memory>
#include <unordered_map>

using namespace asmjit;

class CodeGenerator {
public:
    CodeGenerator();
    ~CodeGenerator();
    
    // Main code generation entry point
    void* generateCode(ASTNode* root);
    
    // Core codegen methods for the basic functionality
    void allocateScope(LexicalScopeNode* scope);
    void assignVariable(VarDeclNode* varDecl, ASTNode* value);
    void printInt64(IdentifierNode* identifier);
    
    // Assembly disassembly and printing
    void disassembleAndPrint(void* code, size_t codeSize);
    
private:
    JitRuntime rt;
    CodeHolder code;
    x86::Builder* cb = nullptr; // Builder pointer - created fresh each time
    csh capstoneHandle;
    
    // Current function context
    LexicalScopeNode* currentScope;
    std::unordered_map<LexicalScopeNode*, x86::Gp> scopeRegisters;
    
    // Helper methods
    void visitNode(ASTNode* node);
    void generateProgram(ASTNode* root);
    void generateLexicalScope(LexicalScopeNode* scope);
    void generateVarDecl(VarDeclNode* varDecl);
    void generatePrintStmt(ASTNode* printStmt);
    void generateFunctionDecl(FunctionDeclNode* funcDecl);
    void generateFunctionCall(FunctionCallNode* funcCall);
    
    // Function-related utilities
    void createFunctionLabel(FunctionDeclNode* funcDecl);
    void generateFunctionPrologue(FunctionDeclNode* funcDecl);
    void generateFunctionEpilogue(FunctionDeclNode* funcDecl);
    void storeFunctionAddressInClosure(FunctionDeclNode* funcDecl, LexicalScopeNode* scope);
    
    // Code generation utilities
    void setupMainFunction();
    void cleanupMainFunction();
    void loadValue(ASTNode* valueNode, x86::Gp destReg);
    void storeVariableInScope(const std::string& varName, x86::Gp valueReg, LexicalScopeNode* scope);
    void loadVariableFromScope(IdentifierNode* identifier, x86::Gp destReg);
    
    // External function declarations
    void declareExternalFunctions();
    Label printInt64Label;
    Label mallocLabel;
    Label freeLabel;
};

// Main interface class expected by main.cpp
class Codegen {
public:
    Codegen();
    ~Codegen();
    
    void generateProgram(ASTNode& root);
    void run();
    
private:
    CodeGenerator generator;
    void* generatedFunction;
};

// External C functions that will be linked
extern "C" {
    void* malloc_wrapper(size_t size);
    void free_wrapper(void* ptr);
}
