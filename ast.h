#pragma once
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <map>
#include <set>
#include <algorithm>
#include <stdexcept>

enum class NodeType {
    PROGRAM, LEXICAL_SCOPE, VAR_DECL, FUNCTION_DECL, FUNCTION_CALL, 
    IDENTIFIER, LITERAL, PRINT_STMT, GO_STMT
};

enum class DataType { INT32, INT64, CLOSURE };

// Forward declarations
class FunctionDeclNode;
class LexicalScopeNode;



struct VariableInfo {
    DataType type;
    std::string name;
    int offset = 0;
    LexicalScopeNode* definedIn = nullptr;
    FunctionDeclNode* funcNode = nullptr; // For closures: back-reference to function
};



class ASTNode {
public:
    NodeType type;
    std::vector<std::unique_ptr<ASTNode>> children;
    std::string value;
    VariableInfo* varRef = nullptr; // For analysis phase
    
    ASTNode(NodeType t, const std::string& v = "") : type(t), value(v) {}
    virtual ~ASTNode() = default;
};

class LexicalScopeNode : public ASTNode {
public:
    std::map<std::string, VariableInfo> variables;
    std::vector<LexicalScopeNode*> children;
    LexicalScopeNode* parentFunctionScope;
    int depth;
    
    std::set<int> parentDeps;    // Parent scope depths this scope depends on
    std::set<int> descendantDeps; // Parent scope depths needed by descendants
    std::vector<int> allNeeded;     // Combined dependencies (parents first, then descendants, no duplicates)
    int totalSize = 0;              // Total packed size of this scope
    
    // For codegen: maps required depth -> parameter index in parent function
    // -1 means it's the immediate parent scope itself (stored in current scope)
    std::map<int, int> scopeDepthToParentParameterIndexMap;
    
    LexicalScopeNode(LexicalScopeNode* p = nullptr, int d = 0) : ASTNode(NodeType::LEXICAL_SCOPE), parentFunctionScope(p), depth(d) {
        if (parentFunctionScope) parentFunctionScope->children.push_back(this);
    }
    
    void updateAllNeeded() {
        allNeeded.clear();
        
        // Add parent deps first
        for (int depthIdx : parentDeps) {
            allNeeded.push_back(depthIdx);
        }
        
        // Add descendant deps that aren't already in parent deps
        for (int depthIdx : descendantDeps) {
            if (parentDeps.find(depthIdx) == parentDeps.end()) {
                allNeeded.push_back(depthIdx);
            }
        }
    }
    
    void buildScopeDepthToParentParameterIndexMap();
    
    int getParameterIndexInCurrentScope(LexicalScopeNode* activeScope) {
        return activeScope->scopeDepthToParentParameterIndexMap.at(this->depth);
    }
    
    void pack() {
        std::vector<std::pair<std::string, VariableInfo*>> vars;
        for (auto& [name, var] : variables) {
            vars.push_back({name, &var});
        }
        
        // Sort by type size (biggest first)
        std::sort(vars.begin(), vars.end(), [](const auto& a, const auto& b) {
            return getTypeSize(*a.second) > getTypeSize(*b.second);
        });
        
        int offset = 0;
        for (auto& [name, var] : vars) {
            int size = getTypeSize(*var);
            int align = var->type == DataType::CLOSURE ? 8 : size; // Closures are pointer-aligned
            offset = (offset + align - 1) & ~(align - 1); // Align
            var->offset = offset;
            offset += size;
        }
        
        // Ensure total size is 8-byte aligned
        totalSize = (offset + 7) & ~7;
    }

private:
    static int getTypeSize(const VariableInfo& var);
};

class VarDeclNode : public ASTNode {
public:
    std::string varName;
    DataType varType;
    
    VarDeclNode(const std::string& name, DataType type) 
        : ASTNode(NodeType::VAR_DECL), varName(name), varType(type) {}
};

class FunctionDeclNode : public LexicalScopeNode {
public:
    std::string funcName;
    std::vector<std::string> params;
    
    FunctionDeclNode(const std::string& name, LexicalScopeNode* p = nullptr) 
        : LexicalScopeNode(p), funcName(name) {
        type = NodeType::FUNCTION_DECL;
        value = name;
    }
};

class IdentifierNode : public ASTNode {
public:
    struct VariableAccess {
        int parameterIndex; // -1 if in current scope, else index in parent params
        int offset;
    };
    
    IdentifierNode(const std::string& name) : ASTNode(NodeType::IDENTIFIER, name) {}
    
    // any time this is accessed it could be in the current scope or in an ancestor scope. Ancestor scopes are passed as "hidden params" after actual params. This function tells us the parameter index of that scope address, and the offset in it we can find this variable at.
    VariableAccess getVariableAccess(LexicalScopeNode* currentScope) {
        if (!varRef) throw std::runtime_error("Variable not analyzed: " + value);
        if (!varRef->definedIn) throw std::runtime_error("Variable scope not found: " + value);
        
        LexicalScopeNode* definingScope = varRef->definedIn;
        
        if (definingScope == currentScope) {
            return {-1, varRef->offset};
        } else {
            int paramIndex = definingScope->getParameterIndexInCurrentScope(currentScope);
            return {paramIndex, varRef->offset};
        }
    }
};

class LiteralNode : public ASTNode {
public:
    LiteralNode(const std::string& val) : ASTNode(NodeType::LITERAL, val) {}
};

class FunctionCallNode : public IdentifierNode {
public:
    std::vector<std::unique_ptr<ASTNode>> args;

    FunctionCallNode(const std::string& name) : IdentifierNode(name) {}
};

// Implementation of getTypeSize after all classes are defined
inline int LexicalScopeNode::getTypeSize(const VariableInfo& var) {
    if (var.type == DataType::CLOSURE && var.funcNode) {
        return 8 + (var.funcNode->allNeeded.size() * 8);
    }
    return var.type == DataType::INT32 ? 4 : 8;
}

// Implementation of buildScopeDepthToParentParameterIndexMap after all classes are defined
inline void LexicalScopeNode::buildScopeDepthToParentParameterIndexMap() {
    scopeDepthToParentParameterIndexMap.clear();
    
    if (!parentFunctionScope) return; // Root scope has no parent
    
    // Only function scopes need parameter mapping
    if (this->type != NodeType::FUNCTION_DECL) return;
    
    // Get the current function's parameter count
    FunctionDeclNode* currentFunc = static_cast<FunctionDeclNode*>(this);
    int currentParamCount = currentFunc->params.size();
    
    // Build map based on what this scope needs and what parent provides
    for (int neededDepth : allNeeded) {
        if (neededDepth == parentFunctionScope->depth) {
            // The needed scope is the immediate parent
            scopeDepthToParentParameterIndexMap[neededDepth] = -1;
        } else {
            // Find where this depth appears in parent's allNeeded array
            auto& parentAllNeeded = parentFunctionScope->allNeeded;
            for (int i = 0; i < (int)parentAllNeeded.size(); i++) {
                if (parentAllNeeded[i] == neededDepth) {
                    // Add current function's parameter count to get final parameter index
                    scopeDepthToParentParameterIndexMap[neededDepth] = currentParamCount + i;
                    break;
                }
            }
        }
    }
}
