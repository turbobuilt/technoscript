#pragma once

#include "ast.h"
#include "gc.h"  // Must be before goroutine.h since goroutine uses GoroutineGCState
#include "library.h"
#include "goroutine.h"
#include <asmjit/asmjit.h>
#include <capstone/capstone.h>
#include <memory>
#include <unordered_map>

using namespace asmjit;

// Metadata structures forward declarations (defined in gc.h)
class ScopeMetadata;
class ClassMetadata;

// Object memory layout constants
namespace ObjectLayout {
    constexpr int FLAGS_OFFSET = 0;
    constexpr int FLAGS_SIZE = 8;
    
    constexpr int CLASS_REF_OFFSET = 8;
    constexpr int CLASS_REF_SIZE = 8;
    
    constexpr int DYNAMIC_VARS_OFFSET = 16;
    constexpr int DYNAMIC_VARS_SIZE = 8;
    
    constexpr int FIELDS_OFFSET = 24;  // 8 + 8 + 8
    constexpr int HEADER_SIZE = 24;    // Total size of object header
}

// Lexical Scope memory layout constants
namespace ScopeLayout {
    constexpr int FLAGS_OFFSET = 0;
    constexpr int FLAGS_SIZE = 8;
    constexpr int METADATA_OFFSET = 8;
    constexpr int METADATA_SIZE = 8;
    constexpr int DATA_OFFSET = 16;     // Parameters/variables start after flags + metadata (was 8)
}

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
    void generateVarDecl(VarDeclNode* varDecl);
    void generateLetDecl(LetDeclNode* letDecl);
    void generatePrintStmt(ASTNode* printStmt);
    void generateFunctionDecl(FunctionDeclNode* funcDecl);
    void generateFunctionCall(FunctionCallNode* funcCall);
    void generateGoStmt(GoStmtNode* goStmt);
    void generateSetTimeoutStmt(SetTimeoutStmtNode* setTimeoutStmt);
    void generateAwaitExpr(ASTNode* awaitExpr, x86::Gp destReg);
    void generateSleepCall(ASTNode* sleepCall, x86::Gp destReg);
    void generateNewExpr(NewExprNode* newExpr, x86::Gp destReg);
    void generateMemberAccess(MemberAccessNode* memberAccess, x86::Gp destReg);
    void generateMemberAssign(MemberAssignNode* memberAssign);
    
    // Function-related utilities
    void createFunctionLabel(FunctionDeclNode* funcDecl);
    void generateFunctionPrologue(FunctionDeclNode* funcDecl);
    void generateFunctionEpilogue(FunctionDeclNode* funcDecl);
    void storeFunctionAddressInClosure(FunctionDeclNode* funcDecl, LexicalScopeNode* scope);
    
    // Generic scope management utilities (shared by functions and blocks)
    void generateScopePrologue(LexicalScopeNode* scope);
    void generateScopeEpilogue(LexicalScopeNode* scope);
    
    // Metadata generation for GC (scope metadata created on-the-fly, class metadata from registry)
    // Note: Returns void* to avoid circular include dependencies
    void* createScopeMetadata(LexicalScopeNode* scope);
    
    // Block statement utilities
    void generateBlockStmt(BlockStmtNode* blockStmt);
    
    // Code generation utilities
    void setupMainFunction();
    void cleanupMainFunction();
    void loadValue(ASTNode* valueNode, x86::Gp destReg);
    void storeVariableInScope(const std::string& varName, x86::Gp valueReg, LexicalScopeNode* scope);
    void loadVariableFromScope(IdentifierNode* identifier, x86::Gp destReg, int offsetInVariable = 0);
    void loadVariableAddress(IdentifierNode* identifier, x86::Gp destReg, int offsetInVariable = 0);
    void loadParameterIntoRegister(int paramIndex, x86::Gp destReg, x86::Gp scopeReg = x86::r15);
    x86::Gp getParameterByIndex(int paramIndex);
    
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
