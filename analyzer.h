#pragma once
#include "ast.h"
#include <unordered_set>

class Analyzer {
private:
    void analyzeScope(LexicalScopeNode* scope);
    void analyzeNode(ASTNode* node, LexicalScopeNode* currentScope);
    VariableInfo* findVariable(const std::string& name, LexicalScopeNode* scope);
    void collectVariables(ASTNode* node, LexicalScopeNode* scope);
    void setupParentPointers(ASTNode* node, LexicalScopeNode* parent, int depth);
    void addParentDep(LexicalScopeNode* scope, int depthIdx);
    void addDescendantDep(LexicalScopeNode* scope, int depthIdx);
    void updateAllNeededArrays(LexicalScopeNode* scope);
    void buildAllScopeIndexMaps(LexicalScopeNode* scope);
    
public:
    void analyze(LexicalScopeNode* root);
};
