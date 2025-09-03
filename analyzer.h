#pragma once
#include "ast.h"

class Analyzer {
private:
    void analyzeScope(LexicalScopeNode* scope);
    void analyzeNode(ASTNode* node, LexicalScopeNode* currentScope);
    VariableInfo* findVariable(const std::string& name, LexicalScopeNode* scope);
    void collectVariables(ASTNode* node, LexicalScopeNode* scope);
    void setupParentPointers(ASTNode* node, LexicalScopeNode* parent);
    
public:
    void analyze(LexicalScopeNode* root);
};
