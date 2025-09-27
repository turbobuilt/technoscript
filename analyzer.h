#pragma once
#include "ast.h"
#include <unordered_set>

class Analyzer {
private:
    // Single-pass analysis method that does everything efficiently
    void analyzeNodeSinglePass(ASTNode* node, LexicalScopeNode* parentScope, int depth);
    
    // Variable resolution (still needed)
    VariableInfo* findVariable(const std::string& name, LexicalScopeNode* scope);
    
    // Dependency tracking helpers
    void addParentDep(LexicalScopeNode* scope, int depthIdx);
    void addDescendantDep(LexicalScopeNode* scope, int depthIdx);
    
public:
    void analyze(LexicalScopeNode* root);
};
