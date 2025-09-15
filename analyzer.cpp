#include "analyzer.h"
#include <iostream>

void Analyzer::analyze(LexicalScopeNode* root) {
    std::cout << "DEBUG Analyzer: Starting collectVariables..." << std::endl;
    collectVariables(root, root);
    std::cout << "DEBUG Analyzer: collectVariables completed" << std::endl;
    
    std::cout << "DEBUG Analyzer: Starting setupParentPointers..." << std::endl;
    setupParentPointers(root, nullptr, 0);
    std::cout << "DEBUG Analyzer: setupParentPointers completed" << std::endl;
    
    std::cout << "DEBUG Analyzer: Starting analyzeScope..." << std::endl;
    analyzeScope(root);
    std::cout << "DEBUG Analyzer: analyzeScope completed" << std::endl;
    
    std::cout << "DEBUG Analyzer: Starting updateAllNeededArrays..." << std::endl;
    updateAllNeededArrays(root);
    std::cout << "DEBUG Analyzer: updateAllNeededArrays completed" << std::endl;
    
    std::cout << "DEBUG Analyzer: Starting packScopes..." << std::endl;
    packScopes(root);
    std::cout << "DEBUG Analyzer: packScopes completed" << std::endl;
    
    std::cout << "DEBUG Analyzer: Starting buildAllScopeDepthToParentParameterIndexMaps..." << std::endl;
    buildAllScopeDepthToParentParameterIndexMaps(root);
    std::cout << "DEBUG Analyzer: buildAllScopeDepthToParentParameterIndexMaps completed" << std::endl;
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
    // Analyze all AST children - this includes function declarations which will recursively analyze their scopes
    for (auto& child : scope->ASTNode::children) {
        analyzeNode(child.get(), scope);
    }
    // No need for separate scope children traversal - function declarations are handled above
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
    std::cout << "DEBUG findVariable: Looking for '" << name << "' from scope depth " << scope->depth << std::endl;
    
    LexicalScopeNode* current = scope->parentFunctionScope;
    LexicalScopeNode* defScope = nullptr;
    int traversal_count = 0;
    
    std::cout << "DEBUG findVariable: Starting parent traversal from scope depth " << scope->depth << std::endl;
    
    // Find where variable is defined
    while (current) {
        traversal_count++;
        std::cout << "DEBUG findVariable: Checking scope depth " << current->depth << " (traversal #" << traversal_count << ")" << std::endl;
        
        if (traversal_count > 20) {
            std::cout << "ERROR findVariable: Excessive traversal (>20) for variable '" << name << "' - possible infinite loop" << std::endl;
            throw std::runtime_error("Infinite loop detected in findVariable for variable: " + name);
        }
        
        auto it = current->variables.find(name);
        if (it != current->variables.end()) {
            std::cout << "DEBUG findVariable: Found '" << name << "' in scope depth " << current->depth << std::endl;
            defScope = current;
            break;
        }
        current = current->parentFunctionScope;
    }
    
    if (defScope) {
        std::cout << "DEBUG findVariable: Adding dependencies for '" << name << "'" << std::endl;
        // Add dependency to current scope
        addParentDep(scope, defScope->depth);
        
        // Add descendant dependencies to all parents up to definition
        LexicalScopeNode* parent = scope->parentFunctionScope;
        int dep_traversal_count = 0;
        while (parent && parent != defScope) {
            dep_traversal_count++;
            std::cout << "DEBUG findVariable: Adding descendant dep to scope depth " << parent->depth << " (dep traversal #" << dep_traversal_count << ")" << std::endl;
            
            if (dep_traversal_count > 20) {
                std::cout << "ERROR findVariable: Excessive dependency traversal (>20) for variable '" << name << "' - possible infinite loop" << std::endl;
                throw std::runtime_error("Infinite loop detected in findVariable dependency traversal for variable: " + name);
            }
            
            addDescendantDep(parent, defScope->depth);
            parent = parent->parentFunctionScope;
        }
        
        std::cout << "DEBUG findVariable: Dependencies added successfully for '" << name << "'" << std::endl;
        return &defScope->variables[name];
    }
    
    // Check current scope
    std::cout << "DEBUG findVariable: Checking current scope for '" << name << "'" << std::endl;
    auto it = scope->variables.find(name);
    if (it != scope->variables.end()) {
        std::cout << "DEBUG findVariable: Found '" << name << "' in current scope" << std::endl;
        return &it->second;
    }
    
    std::cout << "DEBUG findVariable: Variable '" << name << "' not found" << std::endl;
    return nullptr;
}

void Analyzer::addParentDep(LexicalScopeNode* scope, int depthIdx) {
    scope->parentDeps.insert(depthIdx);
}

void Analyzer::addDescendantDep(LexicalScopeNode* scope, int depthIdx) {
    scope->descendantDeps.insert(depthIdx);
}

void Analyzer::updateAllNeededArrays(LexicalScopeNode* scope) {
    printf("DEBUG updateAllNeededArrays: Processing scope at depth %d, type=%d\n", scope->depth, (int)scope->type);
    
    // First, recursively process all child function scopes
    for (auto& child : scope->ASTNode::children) {
        if (child->type == NodeType::FUNCTION_DECL) {
            auto func = static_cast<FunctionDeclNode*>(child.get());
            updateAllNeededArrays(func);
        }
    }
    
    // Then update this scope's allNeeded
    scope->updateAllNeeded();
    
    printf("DEBUG updateAllNeededArrays: Scope depth %d has %zu parent deps, %zu descendant deps, %zu total needed\n", 
           scope->depth, scope->parentDeps.size(), scope->descendantDeps.size(), scope->allNeeded.size());
    
    // Update closure sizes now that allNeeded is calculated
    for (auto& [name, varInfo] : scope->variables) {
        if (varInfo.type == DataType::CLOSURE && varInfo.funcNode) {
            // Calculate correct closure size: 8 bytes for function address + 8 bytes per needed scope
            size_t old_size = varInfo.size;
            printf("DEBUG updateAllNeededArrays: Closure '%s' funcNode=%p, funcNode->allNeeded.size()=%zu\n", 
                   name.c_str(), varInfo.funcNode, varInfo.funcNode->allNeeded.size());
            varInfo.size = 8 + (varInfo.funcNode->allNeeded.size() * 8);
            printf("DEBUG updateAllNeededArrays: Updated closure '%s' size from %zu to %d (needs %zu scopes)\n", 
                   name.c_str(), old_size, varInfo.size, varInfo.funcNode->allNeeded.size());
        }
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
    
    // Recursively pack all function scopes (they're in AST children)
    for (auto& child : scope->ASTNode::children) {
        if (child->type == NodeType::FUNCTION_DECL) {
            auto func = static_cast<FunctionDeclNode*>(child.get());
            packScopes(func);
        }
    }
    // No need for separate scope children traversal - covered above
}
