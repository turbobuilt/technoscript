#pragma once
#include "ast.h"
#include <string>
#include <vector>

enum class TokenType {
    VAR, FUNCTION, GO, IDENTIFIER, INT32_TYPE, INT64_TYPE, LITERAL, 
    ASSIGN, SEMICOLON, LPAREN, RPAREN, LBRACE, RBRACE, 
    COLON, COMMA, STRING, PRINT, SETTIMEOUT, DOT, 
    ASYNC, AWAIT, PROMISE, SLEEP, FOR, LET, LESS_THAN, 
    PLUS_PLUS, CLASS, NEW, THIS, EXTENDS, EOF_TOKEN
};

struct Token {
    TokenType type;
    std::string value;
    Token(TokenType t, const std::string& v = "") : type(t), value(v) {}
};

class Parser {
private:
    std::vector<Token> tokens;
    size_t pos = 0;
    int currentDepth = 0;
    LexicalScopeNode* currentLexicalScope = nullptr;  // Track current lexical scope during parsing
    LexicalScopeNode* currentFunctionScope = nullptr; // Track current function scope during parsing
    std::map<std::string, ClassDeclNode*> classRegistry; // Global registry of all classes
    
    Token& current() { return tokens[pos]; }
    void advance() { if (pos < tokens.size() - 1) pos++; }
    bool match(TokenType t) { return current().type == t; }
    void expect(TokenType t);
    
    // Error recovery method
    bool synchronizeToNextStatement();
    
    // Helper method for error messages
    std::string tokenTypeToString(TokenType type);
    
    std::vector<Token> tokenize(const std::string& code);
    std::unique_ptr<ASTNode> parseStatement(LexicalScopeNode* scope);
    std::unique_ptr<VarDeclNode> parseVarDecl();
    std::unique_ptr<FunctionDeclNode> parseFunctionDecl();
    std::unique_ptr<ASTNode> parseFunctionCall();
    std::unique_ptr<ASTNode> parsePrintStmt();
    std::unique_ptr<ASTNode> parseSetTimeoutStmt();
    std::unique_ptr<ASTNode> parseGoStmt();
    std::unique_ptr<LetDeclNode> parseLetDecl();
    std::unique_ptr<ForStmtNode> parseForStmt();
    std::unique_ptr<BlockStmtNode> parseBlockStmt();
    std::unique_ptr<ASTNode> parseExpression();  // For parsing expressions like i < 2, ++i
    std::unique_ptr<ClassDeclNode> parseClassDecl();
    std::unique_ptr<ASTNode> parsePrimaryExpression(); // For parsing identifiers, member access, new expressions
    
public:
    std::unique_ptr<FunctionDeclNode> parse(const std::string& code);
    const std::map<std::string, ClassDeclNode*>& getClassRegistry() const { return classRegistry; }
};
