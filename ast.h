#pragma once
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <map>
#include <set>

enum class NodeType {
    PROGRAM, LEXICAL_SCOPE, VAR_DECL, FUNCTION_DECL, FUNCTION_CALL, 
    IDENTIFIER, LITERAL, PRINT_STMT, GO_STMT
};

enum class DataType { INT64 };



struct VariableInfo {
    DataType type;
    std::string name;
    int scopeDepth;
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
    LexicalScopeNode* parent;
    int depth;
    
    std::set<int> parentDeps;    // Parent scope depths this scope depends on
    std::set<int> descendantDeps; // Parent scope depths needed by descendants
    std::vector<int> allNeeded;     // Combined dependencies (parents first, then descendants, no duplicates)
    
    // For codegen: maps required depth -> index in parent's scope array
    // -1 means it's the immediate parent scope itself
    std::map<int, int> scopeIndexMap;
    
    LexicalScopeNode(LexicalScopeNode* p = nullptr, int d = 0) : ASTNode(NodeType::LEXICAL_SCOPE), parent(p), depth(d) {
        if (parent) parent->children.push_back(this);
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
    
    void buildScopeIndexMap() {
        scopeIndexMap.clear();
        
        if (!parent) return; // Root scope has no parent
        
        // Build map based on what this scope needs and what parent provides
        for (int neededDepth : allNeeded) {
            if (neededDepth == parent->depth) {
                // The needed scope is the immediate parent
                scopeIndexMap[neededDepth] = -1;
            } else {
                // Find where this depth appears in parent's allNeeded array
                auto& parentAllNeeded = parent->allNeeded;
                for (int i = 0; i < (int)parentAllNeeded.size(); i++) {
                    if (parentAllNeeded[i] == neededDepth) {
                        scopeIndexMap[neededDepth] = i;
                        break;
                    }
                }
            }
        }
    }
};

class VarDeclNode : public ASTNode {
public:
    std::string varName;
    DataType varType;
    
    VarDeclNode(const std::string& name, DataType type) 
        : ASTNode(NodeType::VAR_DECL), varName(name), varType(type) {}
};

class FunctionDeclNode : public ASTNode {
public:
    std::string funcName;
    std::unique_ptr<LexicalScopeNode> scope;
    
    FunctionDeclNode(const std::string& name) 
        : ASTNode(NodeType::FUNCTION_DECL, name), funcName(name) {}
};

class IdentifierNode : public ASTNode {
public:
    IdentifierNode(const std::string& name) : ASTNode(NodeType::IDENTIFIER, name) {}
};

class LiteralNode : public ASTNode {
public:
    LiteralNode(const std::string& val) : ASTNode(NodeType::LITERAL, val) {}
};
