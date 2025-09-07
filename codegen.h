#pragma once
#include "ast.h"
#include "emitter.h"
#include "library.h"
#include <unordered_map>
#include <sys/mman.h>

class Codegen {
private:
    Emitter emitter;
    std::unordered_map<std::string, uint64_t> extern_function_addresses;
    
    // Initialize external function addresses
    void initExternFunctions();
    
    // Allocate memory for lexical scope - returns instruction length
    size_t allocateScope(LexicalScopeNode* scope, bool is_global = false);
    
    // Walk AST and generate code for nodes
    size_t generateNode(ASTNode* node, LexicalScopeNode* current_scope);
    size_t generateVarDecl(VarDeclNode* node, LexicalScopeNode* current_scope);
    size_t generateLiteral(LiteralNode* node);
    size_t generatePrintStatement(ASTNode* node, LexicalScopeNode* current_scope);
    size_t generateIdentifier(IdentifierNode* node, LexicalScopeNode* current_scope);
    
public:
    void generateProgram(ASTNode& root);
    void writeProgramToExecutable();
    
    // Get the raw machine code
    const std::vector<uint8_t>& getCode() const { return emitter.buffer; }
};
