#include "analyzer.h"
#include <iostream>

void Analyzer::analyze(LexicalScopeNode* root) {
    std::cout << "DEBUG Analyzer: Starting single-pass analysis..." << std::endl;
    analyzeNodeSinglePass(root, nullptr, 0);
    std::cout << "DEBUG Analyzer: Single-pass analysis completed" << std::endl;
}

// Single-pass analysis that does everything in the correct order
void Analyzer::analyzeNodeSinglePass(ASTNode* node, LexicalScopeNode* parentScope, int depth) {
    // Prevent infinite recursion
    if (depth > RobustnessLimits::MAX_AST_RECURSION_DEPTH) {
        throw std::runtime_error("AST recursion depth exceeded " + 
                               std::to_string(RobustnessLimits::MAX_AST_RECURSION_DEPTH) + " in single-pass analysis");
    }
    
    LexicalScopeNode* currentScope = parentScope;
    
    // Step 1: Setup parent pointers and depth for scope nodes (on the way down)
    if (node->type == AstNodeType::FUNCTION_DECL) {
        auto scope = static_cast<LexicalScopeNode*>(node);
        scope->parentFunctionScope = parentScope;
        scope->depth = depth;
        currentScope = scope;
        std::cout << "DEBUG: Setup scope at depth " << depth << std::endl;
    }
    
    // Step 2: Analyze current node for variable references
    if (node->type == AstNodeType::IDENTIFIER || node->type == AstNodeType::FUNCTION_CALL) {
        node->varRef = findVariable(node->value, currentScope);
        
        // Set the accessedIn property for identifier nodes
        if (node->type == AstNodeType::IDENTIFIER) {
            auto identifier = static_cast<IdentifierNode*>(node);
            identifier->accessedIn = currentScope;
        } else if (node->type == AstNodeType::FUNCTION_CALL) {
            auto funcCall = static_cast<FunctionCallNode*>(node);
            funcCall->accessedIn = currentScope;
            
            // Analyze function call arguments
            for (auto& arg : funcCall->args) {
                analyzeNodeSinglePass(arg.get(), currentScope, depth + 1);
            }
        }
    }
    
    // Step 3: Recursively process all children
    for (auto& child : node->children) {
        analyzeNodeSinglePass(child.get(), currentScope, depth + 1);
    }
    
    // Step 4: Post-process scope nodes (on the way back up)
    if (node->type == AstNodeType::FUNCTION_DECL) {
        auto scope = static_cast<LexicalScopeNode*>(node);
        
        // Update allNeeded arrays now that all children have been processed
        scope->updateAllNeeded();
        std::cout << "DEBUG: Scope depth " << scope->depth << " has " << scope->allNeeded.size() << " needed scopes" << std::endl;
        
        // Update closure sizes now that allNeeded is calculated
        for (auto& [name, varInfo] : scope->variables) {
            if (varInfo.type == DataType::CLOSURE && varInfo.funcNode) {
                size_t old_size = varInfo.size;
                varInfo.size = 8 + (varInfo.funcNode->allNeeded.size() * 8);
                std::cout << "DEBUG: Updated closure '" << name << "' size from " << old_size 
                         << " to " << varInfo.size << " (needs " << varInfo.funcNode->allNeeded.size() << " scopes)" << std::endl;
            }
        }
        
        // Pack the scope
        scope->pack();
        
        // Build parameter index maps if it's a function scope or the root scope
        scope->buildScopeDepthToParentParameterIndexMap();

        
        std::cout << "DEBUG: Completed post-processing for scope at depth " << scope->depth << std::endl;
    }
}

VariableInfo* Analyzer::findVariable(const std::string& name, LexicalScopeNode* scope) {
    LexicalScopeNode* current = scope;
    LexicalScopeNode* defScope = nullptr;
    
    // Simple lexical scope traversal - check current scope, then parents
    while (current) {
        auto it = current->variables.find(name);
        if (it != current->variables.end()) {
            defScope = current;
            break;
        }
        current = current->parentFunctionScope;
    }
    
    if (!defScope) {
        throw std::runtime_error("Variable '" + name + "' not found in scope");
    }
    
    // Add dependency tracking for closures
    if (defScope != scope) {
        addParentDep(scope, defScope->depth);
        
        // Add descendant dependencies to intermediate scopes
        LexicalScopeNode* parent = scope->parentFunctionScope;
        while (parent && parent != defScope) {
            addDescendantDep(parent, defScope->depth);
            parent = parent->parentFunctionScope;
        }
    }
    
    return &defScope->variables[name];
}

// Helper methods for dependency tracking
void Analyzer::addParentDep(LexicalScopeNode* scope, int depthIdx) {
    scope->parentDeps.insert(depthIdx);
}

void Analyzer::addDescendantDep(LexicalScopeNode* scope, int depthIdx) {
    scope->descendantDeps.insert(depthIdx);
}
