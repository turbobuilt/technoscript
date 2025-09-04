#include "analyzer.h"
#include <iostream>

void Analyzer::analyze(LexicalScopeNode* root) {
    collectVariables(root, root);
    setupParentPointers(root, nullptr, 0);
    analyzeScope(root);
    updateAllNeededArrays(root);
    buildAllScopeIndexMaps(root);
    packScopes(root);
}

void Analyzer::collectVariables(ASTNode* node, LexicalScopeNode* scope) {
    if (node->type == NodeType::VAR_DECL) {
        auto varDecl = static_cast<VarDeclNode*>(node);
        VariableInfo varInfo;
        varInfo.type = varDecl->varType;
        varInfo.name = varDecl->varName;
        varInfo.definedIn = scope;
        scope->variables[varDecl->varName] = varInfo;
    }
    
    if (node->type == NodeType::FUNCTION_DECL) {
        auto func = static_cast<FunctionDeclNode*>(node);
        
        // Create closure variable for function (hoisting)
        VariableInfo closureVar;
        closureVar.type = DataType::CLOSURE;
        closureVar.name = func->funcName;
        closureVar.definedIn = scope;
        closureVar.funcNode = func;
        scope->variables[func->funcName] = closureVar;
        
        // Recursively collect variables in function body
        collectVariables(func->scope.get(), func->scope.get());
    }
    
    for (auto& child : node->children) {
        collectVariables(child.get(), scope);
    }
}

void Analyzer::analyzeScope(LexicalScopeNode* scope) {
    // Analyze the AST children (stored as unique_ptr)
    for (auto& child : scope->ASTNode::children) {
        analyzeNode(child.get(), scope);
    }
    
    // Also analyze the LexicalScopeNode children (raw pointers to other scopes)
    for (auto* child : scope->children) {
        analyzeScope(child);
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
    LexicalScopeNode* current = scope->parent;
    LexicalScopeNode* defScope = nullptr;
    
    // Find where variable is defined
    while (current) {
        auto it = current->variables.find(name);
        if (it != current->variables.end()) {
            defScope = current;
            break;
        }
        current = current->parent;
    }
    
    if (defScope) {
        // Add dependency to current scope
        addParentDep(scope, defScope->depth);
        
        // Add descendant dependencies to all parents up to definition
        LexicalScopeNode* parent = scope->parent;
        while (parent && parent != defScope) {
            addDescendantDep(parent, defScope->depth);
            parent = parent->parent;
        }
        
        return &defScope->variables[name];
    }
    
    // Check current scope
    auto it = scope->variables.find(name);
    if (it != scope->variables.end()) {
        return &it->second;
    }
    
    return nullptr;
}

void Analyzer::addParentDep(LexicalScopeNode* scope, int depthIdx) {
    scope->parentDeps.insert(depthIdx);
}

void Analyzer::addDescendantDep(LexicalScopeNode* scope, int depthIdx) {
    scope->descendantDeps.insert(depthIdx);
}

void Analyzer::updateAllNeededArrays(LexicalScopeNode* scope) {
    scope->updateAllNeeded();
    
    // Recursively update for all function scopes
    for (auto& child : scope->ASTNode::children) {
        if (child->type == NodeType::FUNCTION_DECL) {
            auto func = static_cast<FunctionDeclNode*>(child.get());
            updateAllNeededArrays(func->scope.get());
        }
    }
    
    // Also update for LexicalScopeNode children
    for (auto* child : scope->children) {
        updateAllNeededArrays(child);
    }
}

void Analyzer::buildAllScopeIndexMaps(LexicalScopeNode* scope) {
    scope->buildScopeIndexMap();
    
    // Recursively build maps for all function scopes
    for (auto& child : scope->ASTNode::children) {
        if (child->type == NodeType::FUNCTION_DECL) {
            auto func = static_cast<FunctionDeclNode*>(child.get());
            buildAllScopeIndexMaps(func->scope.get());
        }
    }
    
    // Also build for LexicalScopeNode children
    for (auto* child : scope->children) {
        buildAllScopeIndexMaps(child);
    }
}

void Analyzer::setupParentPointers(ASTNode* node, LexicalScopeNode* parent, int depth) {
    if (node->type == NodeType::LEXICAL_SCOPE) {
        auto scope = static_cast<LexicalScopeNode*>(node);
        scope->parent = parent;
        scope->depth = depth;
        parent = scope;
        depth++;
    }
    
    if (node->type == NodeType::FUNCTION_DECL) {
        auto func = static_cast<FunctionDeclNode*>(node);
        setupParentPointers(func->scope.get(), parent, depth);
    }
    
    for (auto& child : node->children) {
        setupParentPointers(child.get(), parent, depth);
    }
}

void Analyzer::packScopes(LexicalScopeNode* scope) {
    scope->pack();
    
    // Recursively pack all function scopes
    for (auto& child : scope->ASTNode::children) {
        if (child->type == NodeType::FUNCTION_DECL) {
            auto func = static_cast<FunctionDeclNode*>(child.get());
            packScopes(func->scope.get());
        }
    }
    
    // Also pack LexicalScopeNode children
    for (auto* child : scope->children) {
        packScopes(child);
    }
}
