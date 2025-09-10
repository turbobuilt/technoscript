#include "analyzer.h"
#include <iostream>

void Analyzer::analyze(LexicalScopeNode* root) {
    collectVariables(root, root);
    setupParentPointers(root, nullptr, 0);
    analyzeScope(root);
    updateAllNeededArrays(root);
    buildAllScopeDepthToParentParameterIndexMaps(root);
    packScopes(root);
}

void Analyzer::collectVariables(ASTNode* node, LexicalScopeNode* scope) {
    if (node->type == NodeType::VAR_DECL) {
        auto varDecl = static_cast<VarDeclNode*>(node);
        VariableInfo varInfo;
        varInfo.type = varDecl->varType;
        varInfo.name = varDecl->varName;
        varInfo.definedIn = scope;
        // Set size based on type
        if (varDecl->varType == DataType::INT32) {
            varInfo.size = 4;
        } else {
            varInfo.size = 8; // INT64 and other types
        }
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
        closureVar.size = 8; // Temporary size, will be updated after analysis
        scope->variables[func->funcName] = closureVar;
        
        // Add function parameters as variables in the function scope
        for (const std::string& paramName : func->params) {
            VariableInfo paramVar;
            paramVar.type = DataType::INT64; // Default type for now (should be improved with actual type analysis)
            paramVar.name = paramName;
            paramVar.definedIn = func;
            paramVar.size = 8; // Parameters are 8 bytes
            func->variables[paramName] = paramVar;
        }
        
        // Recursively collect variables in function body (children, not the function itself)
        for (auto& child : func->ASTNode::children) {
            collectVariables(child.get(), func);
        }
        return; // Don't process children again below
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
    if (node->type == NodeType::IDENTIFIER || node->type == NodeType::FUNCTION_CALL) {
        node->varRef = findVariable(node->value, currentScope);
        
        // Set the accessedIn property for identifier nodes
        if (node->type == NodeType::IDENTIFIER) {
            auto identifier = static_cast<IdentifierNode*>(node);
            identifier->accessedIn = currentScope;
        } else if (node->type == NodeType::FUNCTION_CALL) {
            auto funcCall = static_cast<FunctionCallNode*>(node);
            funcCall->accessedIn = currentScope;
        }
    }
    
    if (node->type == NodeType::FUNCTION_DECL) {
        auto func = static_cast<FunctionDeclNode*>(node);
        analyzeScope(func);
        return;
    }
    
    // Special handling for function calls - analyze their arguments
    if (node->type == NodeType::FUNCTION_CALL) {
        auto funcCall = static_cast<FunctionCallNode*>(node);
        for (auto& arg : funcCall->args) {
            analyzeNode(arg.get(), currentScope);
        }
    }
    
    for (auto& child : node->children) {
        analyzeNode(child.get(), currentScope);
    }
}

VariableInfo* Analyzer::findVariable(const std::string& name, LexicalScopeNode* scope) {
    LexicalScopeNode* current = scope->parentFunctionScope;
    LexicalScopeNode* defScope = nullptr;
    
    // Find where variable is defined
    while (current) {
        auto it = current->variables.find(name);
        if (it != current->variables.end()) {
            defScope = current;
            break;
        }
        current = current->parentFunctionScope;
    }
    
    if (defScope) {
        // Add dependency to current scope
        addParentDep(scope, defScope->depth);
        
        // Add descendant dependencies to all parents up to definition
        LexicalScopeNode* parent = scope->parentFunctionScope;
        while (parent && parent != defScope) {
            addDescendantDep(parent, defScope->depth);
            parent = parent->parentFunctionScope;
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
    
    // Update closure sizes now that allNeeded is calculated
    for (auto& [name, varInfo] : scope->variables) {
        if (varInfo.type == DataType::CLOSURE && varInfo.funcNode) {
            // Calculate correct closure size: 8 bytes for function address + 8 bytes per needed scope
            varInfo.size = 8 + (varInfo.funcNode->allNeeded.size() * 8);
        }
    }
    
    // Recursively update for all function scopes
    for (auto& child : scope->ASTNode::children) {
        if (child->type == NodeType::FUNCTION_DECL) {
            auto func = static_cast<FunctionDeclNode*>(child.get());
            updateAllNeededArrays(func);
        }
    }
    
    // Also update for LexicalScopeNode children
    for (auto* child : scope->children) {
        updateAllNeededArrays(child);
    }
}

void Analyzer::buildAllScopeDepthToParentParameterIndexMaps(LexicalScopeNode* scope) {
    scope->buildScopeDepthToParentParameterIndexMap();
    
    // Traverse AST children (not scope children)
    for (auto& child : scope->ASTNode::children) {
        if (child->type == NodeType::FUNCTION_DECL || child->type == NodeType::LEXICAL_SCOPE) {
            LexicalScopeNode* childScope = static_cast<LexicalScopeNode*>(child.get());
            buildAllScopeDepthToParentParameterIndexMaps(childScope);
        }
    }
}

void Analyzer::setupParentPointers(ASTNode* node, LexicalScopeNode* parent, int depth) {
    if (node->type == NodeType::LEXICAL_SCOPE || node->type == NodeType::FUNCTION_DECL) {
        auto scope = static_cast<LexicalScopeNode*>(node);
        scope->parentFunctionScope = parent;
        scope->depth = depth;
        parent = scope;
        depth++;
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
            packScopes(func);
        }
    }
    
    // Also pack LexicalScopeNode children
    for (auto* child : scope->children) {
        packScopes(child);
    }
}
