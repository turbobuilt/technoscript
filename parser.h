#pragma once
#include "ast.h"
#include <string>
#include <vector>

enum class TokenType {
    VAR, FUNCTION, GO, IDENTIFIER, INT32_TYPE, INT64_TYPE, LITERAL, 
    ASSIGN, SEMICOLON, LPAREN, RPAREN, LBRACE, RBRACE, LBRACKET, RBRACKET,
    COLON, COMMA, STRING, PRINT, SETTIMEOUT, DOT, 
    ASYNC, AWAIT, PROMISE, SLEEP, FOR, LET, LESS_THAN, 
    PLUS_PLUS, CLASS, NEW, THIS, EXTENDS, EOF_TOKEN
};

struct Token {
    TokenType type;
    std::string value;
    size_t line;
    size_t column;
    size_t position;  // Absolute position in source
    Token(TokenType t, const std::string& v = "", size_t l = 0, size_t c = 0, size_t p = 0) 
        : type(t), value(v), line(l), column(c), position(p) {}
};

class Parser {
private:
    std::vector<Token> tokens;
    size_t pos = 0;
    int currentDepth = 0;
    LexicalScopeNode* currentLexicalScope = nullptr;  // Track current lexical scope during parsing
    LexicalScopeNode* currentFunctionScope = nullptr; // Track current function scope during parsing
    std::map<std::string, ClassDeclNode*> classRegistry; // Global registry of all classes
    std::vector<FunctionDeclNode*> functionRegistry;  // Registry of all functions including methods
    std::string sourceCode;  // Store original source code for error reporting
    
    Token& current() { return tokens[pos]; }
    void advance() { if (pos < tokens.size() - 1) pos++; }
    bool match(TokenType t) { return current().type == t; }
    bool matchNext(TokenType t) { return (pos + 1 < tokens.size()) && tokens[pos + 1].type == t; }
    bool matchOffset(int offset, TokenType t) { return (pos + offset < tokens.size()) && tokens[pos + offset].type == t; }
    void expect(TokenType t);
    
    // Error recovery method
    bool synchronizeToNextStatement();
    
    // Helper method for error messages
    std::string tokenTypeToString(TokenType type);
    
    // Enhanced error reporting
    void displayError(const std::string& message, const Token& token);
    
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
    const std::vector<FunctionDeclNode*>& getFunctionRegistry() const { return functionRegistry; }
};
