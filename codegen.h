#pragma once
#include "ast.h"
#include "emitter.h"
#include "library.h"
#include <unordered_map>
#include <sys/mman.h>

// Structure to track function address patches
struct FunctionPatch {
    size_t offset_in_buffer;     // Exact offset in machine code where 8-byte address needs to be patched
    FunctionDeclNode* func;      // Function node to get address from later
};

class Codegen {
private:
    Emitter emitter;
    std::unordered_map<std::string, uint64_t> extern_function_addresses;
    std::vector<FunctionPatch> function_patches; // Patches to apply later
    
    // Initialize external function addresses
    void initExternFunctions();
    
    // Allocate memory for lexical scope - returns instruction length
    size_t allocateScope(LexicalScopeNode* scope, bool is_global = false);
    
    // Restore previous lexical scope - returns instruction length
    size_t restoreScope();
    
    // Create closures in the current scope - returns instruction length
    size_t createClosures(LexicalScopeNode* scope);
    
    // Patch all function addresses before execution
    void patchFunctionAddresses();
    
    // Walk AST and generate code for nodes
    size_t generateNode(ASTNode* node, LexicalScopeNode* current_scope);
    size_t generateVarDecl(VarDeclNode* node, LexicalScopeNode* current_scope);
    size_t generateLiteral(LiteralNode* node);
    size_t generatePrintStatement(ASTNode* node, LexicalScopeNode* current_scope);
    size_t generateIdentifier(IdentifierNode* node, LexicalScopeNode* current_scope);
    size_t generateFunctionCall(FunctionCallNode* node, LexicalScopeNode* current_scope);
    
public:
    void generateProgram(ASTNode& root);
    void writeProgramToExecutable();
    
    // Get the raw machine code
    const std::vector<uint8_t>& getCode() const { return emitter.buffer; }
};
