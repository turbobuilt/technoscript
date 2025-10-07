#pragma once
#include "ast.h"
#include <unordered_set>
#include <map>

class Analyzer {
private:
    const std::map<std::string, ClassDeclNode*>* classRegistry = nullptr; // Reference to parser's class registry
    FunctionDeclNode* currentMethodContext = nullptr; // Track which method we're currently analyzing
    ClassDeclNode* currentClassContext = nullptr;     // Track which class the current method belongs to
    
    // Single-pass analysis method that does everything efficiently
    void analyzeNodeSinglePass(ASTNode* node, LexicalScopeNode* parentScope, int depth);
    
    // Variable resolution (still needed)
    VariableInfo* findVariable(const std::string& name, LexicalScopeNode* scope);
    
    // Class resolution
    ClassDeclNode* findClass(const std::string& className);
    
    // Class inheritance helpers (called once per class during first pass)
    void resolveClassInheritance(ClassDeclNode* classDecl);
    void calculateClassLayout(ClassDeclNode* classDecl);
    void buildClassVTable(ClassDeclNode* classDecl);
    
    // Method resolution for method calls
    ClassDeclNode::VTableEntry* findMethodInClass(ClassDeclNode* classDecl, const std::string& methodName);
    
    // Dependency tracking helpers
    void addParentDep(LexicalScopeNode* scope, int depthIdx);
    void addDescendantDep(LexicalScopeNode* scope, int depthIdx);
    
public:
    void analyze(LexicalScopeNode* root, const std::map<std::string, ClassDeclNode*>& classes);
};
