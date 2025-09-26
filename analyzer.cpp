#include "analyzer.h"
#include <iostream>

void Analyzer::analyze(LexicalScopeNode* root) {
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

    
void Analyzer::analyzeScope(LexicalScopeNode* scope, int depth) {
    // Prevent infinite recursion
    if (depth > RobustnessLimits::MAX_AST_RECURSION_DEPTH) {
        throw std::runtime_error("AST recursion depth exceeded " + 
                               std::to_string(RobustnessLimits::MAX_AST_RECURSION_DEPTH) + " in analyzeScope");
    }
    
    // Analyze all AST children - this includes function declarations which will recursively analyze their scopes
    for (auto& child : scope->ASTNode::children) {
        analyzeNode(child.get(), scope, depth + 1);
    }
    // No need for separate scope children traversal - function declarations are handled above
}

void Analyzer::analyzeNode(ASTNode* node, LexicalScopeNode* currentScope, int depth) {
    // Prevent infinite recursion
    if (depth > RobustnessLimits::MAX_AST_RECURSION_DEPTH) {
        throw std::runtime_error("AST recursion depth exceeded " + 
                               std::to_string(RobustnessLimits::MAX_AST_RECURSION_DEPTH) + " in analyzeNode");
    }
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
        analyzeScope(func, depth + 1);
        return;
    }
    
    // Special handling for function calls - analyze their arguments
    if (node->type == NodeType::FUNCTION_CALL) {
        auto funcCall = static_cast<FunctionCallNode*>(node);
        for (auto& arg : funcCall->args) {
            analyzeNode(arg.get(), currentScope, depth + 1);
        }
    }
    
    for (auto& child : node->children) {
        analyzeNode(child.get(), currentScope, depth + 1);
    }
}

VariableInfo* Analyzer::findVariable(const std::string& name, LexicalScopeNode* scope) {
    std::cout << "DEBUG findVariable: Looking for '" << name << "' from scope depth " << scope->depth << std::endl;
    
    LexicalScopeNode* current = scope->parentFunctionScope;
    LexicalScopeNode* defScope = nullptr;
    int traversal_count = 0;
    std::set<LexicalScopeNode*> visitedScopes; // Track visited scopes to detect cycles
    
    std::cout << "DEBUG findVariable: Starting parent traversal from scope depth " << scope->depth << std::endl;
    
    // Find where variable is defined
    while (current) {
        traversal_count++;
        std::cout << "DEBUG findVariable: Checking scope depth " << current->depth << " (traversal #" << traversal_count << ")" << std::endl;
        
        // Check for cycles in parent chain
        if (visitedScopes.find(current) != visitedScopes.end()) {
            throw std::runtime_error("Cycle detected in parent scope chain for variable: " + name);
        }
        visitedScopes.insert(current);
        
        if (traversal_count > RobustnessLimits::MAX_SCOPE_TRAVERSAL_DEPTH) {
            std::cout << "ERROR findVariable: Excessive traversal (>" << RobustnessLimits::MAX_SCOPE_TRAVERSAL_DEPTH 
                     << ") for variable '" << name << "' - possible infinite loop" << std::endl;
            throw std::runtime_error("Scope traversal depth exceeded for variable: " + name);
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
        std::set<LexicalScopeNode*> depVisitedScopes; // Track visited scopes in dependency traversal
        
        while (parent && parent != defScope) {
            dep_traversal_count++;
            std::cout << "DEBUG findVariable: Adding descendant dep to scope depth " << parent->depth << " (dep traversal #" << dep_traversal_count << ")" << std::endl;
            
            // Check for cycles in dependency traversal
            if (depVisitedScopes.find(parent) != depVisitedScopes.end()) {
                throw std::runtime_error("Cycle detected in dependency traversal for variable: " + name);
            }
            depVisitedScopes.insert(parent);
            
            if (dep_traversal_count > RobustnessLimits::MAX_SCOPE_TRAVERSAL_DEPTH) {
                std::cout << "ERROR findVariable: Excessive dependency traversal (>" << RobustnessLimits::MAX_SCOPE_TRAVERSAL_DEPTH 
                         << ") for variable '" << name << "' - possible infinite loop" << std::endl;
                throw std::runtime_error("Dependency traversal depth exceeded for variable: " + name);
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

void Analyzer::updateAllNeededArrays(LexicalScopeNode* scope, int depth) {
    // Prevent infinite recursion
    if (depth > RobustnessLimits::MAX_AST_RECURSION_DEPTH) {
        throw std::runtime_error("AST recursion depth exceeded " + 
                               std::to_string(RobustnessLimits::MAX_AST_RECURSION_DEPTH) + " in updateAllNeededArrays");
    }
    
    printf("DEBUG updateAllNeededArrays: Processing scope at depth %d, type=%d, recursion depth=%d\n", 
           scope->depth, (int)scope->type, depth);
    
    // First, recursively process all child function scopes
    for (auto& child : scope->ASTNode::children) {
        if (child->type == NodeType::FUNCTION_DECL) {
            auto func = static_cast<FunctionDeclNode*>(child.get());
            updateAllNeededArrays(func, depth + 1);
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

void Analyzer::buildAllScopeDepthToParentParameterIndexMaps(LexicalScopeNode* scope, int depth) {
    // Prevent infinite recursion
    if (depth > RobustnessLimits::MAX_AST_RECURSION_DEPTH) {
        throw std::runtime_error("AST recursion depth exceeded " + 
                               std::to_string(RobustnessLimits::MAX_AST_RECURSION_DEPTH) + " in buildAllScopeDepthToParentParameterIndexMaps");
    }
    
    scope->buildScopeDepthToParentParameterIndexMap();
    
    // Traverse AST children (not scope children)
    for (auto& child : scope->ASTNode::children) {
        if (child->type == NodeType::FUNCTION_DECL || child->type == NodeType::LEXICAL_SCOPE) {
            LexicalScopeNode* childScope = static_cast<LexicalScopeNode*>(child.get());
            buildAllScopeDepthToParentParameterIndexMaps(childScope, depth + 1);
        }
    }
}

void Analyzer::setupParentPointers(ASTNode* node, LexicalScopeNode* parent, int depth) {
    // Prevent infinite recursion
    if (depth > RobustnessLimits::MAX_AST_RECURSION_DEPTH) {
        throw std::runtime_error("AST recursion depth exceeded " + 
                               std::to_string(RobustnessLimits::MAX_AST_RECURSION_DEPTH) + " in setupParentPointers");
    }
    if (node->type == NodeType::LEXICAL_SCOPE || node->type == NodeType::FUNCTION_DECL) {
        auto scope = static_cast<LexicalScopeNode*>(node);
        scope->parentFunctionScope = parent;
        scope->depth = depth;
        parent = scope;
        depth++;
    }
    
    for (auto& child : node->children) {
        setupParentPointers(child.get(), parent, depth + 1);
    }
}

void Analyzer::packScopes(LexicalScopeNode* scope, int depth) {
    // Prevent infinite recursion
    if (depth > RobustnessLimits::MAX_AST_RECURSION_DEPTH) {
        throw std::runtime_error("AST recursion depth exceeded " + 
                               std::to_string(RobustnessLimits::MAX_AST_RECURSION_DEPTH) + " in packScopes");
    }
    
    scope->pack();
    
    // Recursively pack all function scopes (they're in AST children)
    for (auto& child : scope->ASTNode::children) {
        if (child->type == NodeType::FUNCTION_DECL) {
            auto func = static_cast<FunctionDeclNode*>(child.get());
            packScopes(func, depth + 1);
        }
    }
    // No need for separate scope children traversal - covered above
}
