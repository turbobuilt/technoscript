#pragma once
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>

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
    std::unordered_map<std::string, std::unique_ptr<VariableInfo>> variables;
    int depth;
    LexicalScopeNode* parent = nullptr;
    
    LexicalScopeNode(int d, LexicalScopeNode* p = nullptr) 
        : ASTNode(NodeType::LEXICAL_SCOPE), depth(d), parent(p) {}
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
