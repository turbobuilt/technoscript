#pragma once
#include "ast.h"
#include <unordered_set>

class Analyzer {
private:
    void analyzeScope(LexicalScopeNode* scope, int depth = 0);
    void analyzeNode(ASTNode* node, LexicalScopeNode* currentScope, int depth = 0);
    VariableInfo* findVariable(const std::string& name, LexicalScopeNode* scope);
    void setupParentPointers(ASTNode* node, LexicalScopeNode* parent, int depth);
    void addParentDep(LexicalScopeNode* scope, int depthIdx);
    void addDescendantDep(LexicalScopeNode* scope, int depthIdx);
    void updateAllNeededArrays(LexicalScopeNode* scope, int depth = 0);
    void buildAllScopeDepthToParentParameterIndexMaps(LexicalScopeNode* scope, int depth = 0);
    void packScopes(LexicalScopeNode* scope, int depth = 0);
    
public:
    void analyze(LexicalScopeNode* root);
};
