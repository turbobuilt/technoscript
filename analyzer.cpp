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
    if (node->type == AstNodeType::FUNCTION_DECL || node->type == AstNodeType::FOR_STMT || node->type == AstNodeType::BLOCK_STMT) {
        auto scope = static_cast<LexicalScopeNode*>(node);
        scope->parentFunctionScope = parentScope;
        scope->depth = depth;
        currentScope = scope;
        std::string typeStr = (node->type == AstNodeType::FUNCTION_DECL) ? "FUNCTION" : 
                             (node->type == AstNodeType::FOR_STMT) ? "FOR" : "BLOCK";
        std::cout << "DEBUG: Setup scope at depth " << depth << " (type: " << typeStr << ")" << std::endl;
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
    } else if (node->type == AstNodeType::SETTIMEOUT_STMT) {
        // Analyze setTimeout statement - need to resolve function name and delay
        auto setTimeoutStmt = static_cast<SetTimeoutStmtNode*>(node);
        
        // Analyze the function name identifier
        if (setTimeoutStmt->functionName) {
            analyzeNodeSinglePass(setTimeoutStmt->functionName.get(), currentScope, depth + 1);
        }
        
        // Analyze the delay literal
        if (setTimeoutStmt->delay) {
            analyzeNodeSinglePass(setTimeoutStmt->delay.get(), currentScope, depth + 1);
        }
    } else if (node->type == AstNodeType::FOR_STMT) {
        // Special handling for for loop - need to analyze init, condition, update in the for loop's scope
        auto forStmt = static_cast<ForStmtNode*>(node);
        
        // Analyze initialization (e.g., let i: int64 = 0) in the for loop's own scope
        if (forStmt->init) {
            analyzeNodeSinglePass(forStmt->init.get(), currentScope, depth + 1);
        }
        
        // Analyze condition (e.g., i < 2) in the for loop's scope
        if (forStmt->condition) {
            analyzeNodeSinglePass(forStmt->condition.get(), currentScope, depth + 1);
        }
        
        // Analyze update (e.g., ++i) in the for loop's scope  
        if (forStmt->update) {
            analyzeNodeSinglePass(forStmt->update.get(), currentScope, depth + 1);
        }
    } else if (node->type == AstNodeType::BINARY_EXPR) {
        // Handle binary expressions - analyze left and right operands
        auto binaryExpr = static_cast<BinaryExprNode*>(node);
        if (binaryExpr->left) {
            analyzeNodeSinglePass(binaryExpr->left.get(), currentScope, depth + 1);
        }
        if (binaryExpr->right) {
            analyzeNodeSinglePass(binaryExpr->right.get(), currentScope, depth + 1);
        }
    } else if (node->type == AstNodeType::UNARY_EXPR) {
        // Handle unary expressions - analyze the operand
        auto unaryExpr = static_cast<UnaryExprNode*>(node);
        if (unaryExpr->operand) {
            analyzeNodeSinglePass(unaryExpr->operand.get(), currentScope, depth + 1);
        }
    }
    
    // Step 3: Recursively process all children
    for (auto& child : node->children) {
        analyzeNodeSinglePass(child.get(), currentScope, depth + 1);
    }
    
    // Step 4: Post-process scope nodes (on the way back up)
    if (node->type == AstNodeType::FUNCTION_DECL || node->type == AstNodeType::FOR_STMT || node->type == AstNodeType::BLOCK_STMT) {
        auto scope = static_cast<LexicalScopeNode*>(node);
        
        // Update allNeeded arrays now that all children have been processed
        scope->updateAllNeeded();
        std::cout << "DEBUG: Scope depth " << scope->depth << " has " << scope->allNeeded.size() << " needed scopes" << std::endl;
        
        // For function scopes, update closure sizes now that allNeeded is calculated
        if (node->type == AstNodeType::FUNCTION_DECL) {
            for (auto& [name, varInfo] : scope->variables) {
                if (varInfo.type == DataType::CLOSURE && varInfo.funcNode) {
                    size_t old_size = varInfo.size;
                    // New closure layout: [function_address] [size] [scope_pointer_1] ... [scope_pointer_N]
                    varInfo.size = 8 + 8 + (varInfo.funcNode->allNeeded.size() * 8); // function + size + scopes
                    std::cout << "DEBUG: Updated closure '" << name << "' size from " << old_size 
                             << " to " << varInfo.size << " (needs " << varInfo.funcNode->allNeeded.size() << " scopes)" << std::endl;
                }
            }
        }
        
        // Pack the scope
        scope->pack();
        
        // Build parameter index maps if it's a function scope or block scope
        if (node->type == AstNodeType::FUNCTION_DECL || node->type == AstNodeType::BLOCK_STMT) {
            scope->buildScopeDepthToParentParameterIndexMap();
        }

        
        std::cout << "DEBUG: Completed post-processing for scope at depth " << scope->depth << std::endl;
    }
}

VariableInfo* Analyzer::findVariable(const std::string& name, LexicalScopeNode* scope) {
    std::cout << "DEBUG findVariable: Looking for '" << name << "' in scope at depth " << (scope ? scope->depth : -1) << std::endl;
    
    LexicalScopeNode* current = scope;
    LexicalScopeNode* defScope = nullptr;
    
    // Simple lexical scope traversal - check current scope, then parents
    while (current) {
        std::cout << "DEBUG findVariable: Checking scope at depth " << current->depth << " with " << current->variables.size() << " variables" << std::endl;
        for (const auto& [varName, varInfo] : current->variables) {
            std::cout << "DEBUG findVariable:   - Found variable '" << varName << "'" << std::endl;
        }
        
        auto it = current->variables.find(name);
        if (it != current->variables.end()) {
            std::cout << "DEBUG findVariable: Found '" << name << "' in scope at depth " << current->depth << std::endl;
            defScope = current;
            break;
        }
        current = current->parentFunctionScope;
    }
    
    if (!defScope) {
        std::cout << "DEBUG findVariable: Variable '" << name << "' NOT FOUND" << std::endl;
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
