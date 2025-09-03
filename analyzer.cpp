#include "analyzer.h"

void Analyzer::analyze(LexicalScopeNode* root) {
    collectVariables(root, root);
    setupParentPointers(root, nullptr);
    analyzeScope(root);
}

void Analyzer::collectVariables(ASTNode* node, LexicalScopeNode* scope) {
    if (node->type == NodeType::VAR_DECL) {
        auto varDecl = static_cast<VarDeclNode*>(node);
        auto varInfo = std::make_unique<VariableInfo>();
        varInfo->type = varDecl->varType;
        varInfo->name = varDecl->varName;
        varInfo->scopeDepth = scope->depth;
        scope->variables[varDecl->varName] = std::move(varInfo);
    }
    
    if (node->type == NodeType::FUNCTION_DECL) {
        auto func = static_cast<FunctionDeclNode*>(node);
        collectVariables(func->scope.get(), func->scope.get());
    }
    
    for (auto& child : node->children) {
        collectVariables(child.get(), scope);
    }
}

void Analyzer::analyzeScope(LexicalScopeNode* scope) {
    for (auto& child : scope->children) {
        analyzeNode(child.get(), scope);
    }
}

void Analyzer::analyzeNode(ASTNode* node, LexicalScopeNode* currentScope) {
    if (node->type == NodeType::IDENTIFIER) {
        node->varRef = findVariable(node->value, currentScope);
    }
    
    if (node->type == NodeType::FUNCTION_DECL) {
        auto func = static_cast<FunctionDeclNode*>(node);
        analyzeScope(func->scope.get());
        return;
    }
    
    for (auto& child : node->children) {
        analyzeNode(child.get(), currentScope);
    }
}

VariableInfo* Analyzer::findVariable(const std::string& name, LexicalScopeNode* scope) {
    LexicalScopeNode* current = scope;
    while (current) {
        auto it = current->variables.find(name);
        if (it != current->variables.end()) {
            return it->second.get();
        }
        current = current->parent;
    }
    return nullptr;
}

void Analyzer::setupParentPointers(ASTNode* node, LexicalScopeNode* parent) {
    if (node->type == NodeType::LEXICAL_SCOPE) {
        auto scope = static_cast<LexicalScopeNode*>(node);
        scope->parent = parent;
        parent = scope;
    }
    
    if (node->type == NodeType::FUNCTION_DECL) {
        auto func = static_cast<FunctionDeclNode*>(node);
        setupParentPointers(func->scope.get(), parent);
    }
    
    for (auto& child : node->children) {
        setupParentPointers(child.get(), parent);
    }
}


