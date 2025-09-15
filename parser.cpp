#include "parser.h"
#include <stdexcept>
#include <cctype>
#include <iostream>

void Parser::expect(TokenType t) {
    if (current().type != t) throw std::runtime_error("Unexpected token");
    advance();
}

std::vector<Token> Parser::tokenize(const std::string& code) {
    std::vector<Token> result;
    size_t i = 0;
    
    while (i < code.length()) {
        if (std::isspace(code[i])) { i++; continue; }
        
        if (std::isalpha(code[i])) {
            std::string word;
            while (i < code.length() && (std::isalnum(code[i]) || code[i] == '_')) 
                word += code[i++];
            
            if (word == "var") result.emplace_back(TokenType::VAR);
            else if (word == "function") result.emplace_back(TokenType::FUNCTION);
            else if (word == "go") result.emplace_back(TokenType::GO);
            else if (word == "int32") result.emplace_back(TokenType::INT32_TYPE);
            else if (word == "int64") result.emplace_back(TokenType::INT64_TYPE);
            else if (word == "print") result.emplace_back(TokenType::PRINT);
            else result.emplace_back(TokenType::IDENTIFIER, word);
        }
        else if (std::isdigit(code[i])) {
            std::string num;
            while (i < code.length() && std::isdigit(code[i])) num += code[i++];
            result.emplace_back(TokenType::LITERAL, num);
        }
        else if (code[i] == '"') {
            std::string str;
            i++;
            while (i < code.length() && code[i] != '"') str += code[i++];
            if (i < code.length()) i++;
            result.emplace_back(TokenType::STRING, str);
        }
        else {
            switch (code[i++]) {
                case '=': result.emplace_back(TokenType::ASSIGN); break;
                case ';': result.emplace_back(TokenType::SEMICOLON); break;
                case '(': result.emplace_back(TokenType::LPAREN); break;
                case ')': result.emplace_back(TokenType::RPAREN); break;
                case '{': result.emplace_back(TokenType::LBRACE); break;
                case '}': result.emplace_back(TokenType::RBRACE); break;
                case ':': result.emplace_back(TokenType::COLON); break;
                case ',': result.emplace_back(TokenType::COMMA); break;
                case '.': result.emplace_back(TokenType::DOT); break;
            }
        }
    }
    result.emplace_back(TokenType::EOF_TOKEN);
    return result;
}

std::unique_ptr<LexicalScopeNode> Parser::parse(const std::string& code) {
    tokens = tokenize(code);
    pos = 0;
    currentDepth = 0;
    auto root = std::make_unique<LexicalScopeNode>(nullptr, 0);
    
    while (!match(TokenType::EOF_TOKEN)) {
        auto stmt = parseStatement(root.get());
        if (stmt) root->ASTNode::children.push_back(std::move(stmt));
    }
    return root;
}

std::unique_ptr<ASTNode> Parser::parseStatement(LexicalScopeNode* scope) {
    if (match(TokenType::VAR)) return parseVarDecl();
    if (match(TokenType::FUNCTION)) return parseFunctionDecl();
    if (match(TokenType::PRINT)) return parsePrintStmt();
    if (match(TokenType::GO)) return parseGoStmt();
    if (match(TokenType::IDENTIFIER)) {
        // Check for console.log pattern
        if (current().value == "console" && 
            pos + 1 < tokens.size() && tokens[pos + 1].type == TokenType::DOT &&
            pos + 2 < tokens.size() && tokens[pos + 2].type == TokenType::IDENTIFIER && 
            tokens[pos + 2].value == "log") {
            // Skip "console", ".", "log" tokens
            advance(); // skip "console"
            advance(); // skip "."
            advance(); // skip "log"
            
            // Parse as print statement
            expect(TokenType::LPAREN);
            
            auto print = std::make_unique<ASTNode>(NodeType::PRINT_STMT);
            while (!match(TokenType::RPAREN)) {
                if (match(TokenType::STRING)) {
                    print->children.push_back(std::make_unique<LiteralNode>(current().value));
                    advance();
                } else if (match(TokenType::LITERAL)) {
                    print->children.push_back(std::make_unique<LiteralNode>(current().value));
                    advance();
                } else if (match(TokenType::IDENTIFIER)) {
                    print->children.push_back(std::make_unique<IdentifierNode>(current().value));
                    advance();
                }
                if (match(TokenType::COMMA)) advance();
            }
            expect(TokenType::RPAREN);
            return print;
        }
        // Look ahead to see if this is a function call
        else if (pos + 1 < tokens.size() && tokens[pos + 1].type == TokenType::LPAREN) {
            return parseFunctionCall();
        } else {
            // Just return an identifier node
            auto identifier = std::make_unique<IdentifierNode>(current().value);
            advance();
            return identifier;
        }
    }
    return nullptr;
}

std::unique_ptr<VarDeclNode> Parser::parseVarDecl() {
    expect(TokenType::VAR);
    std::string name = current().value;
    expect(TokenType::IDENTIFIER);
    expect(TokenType::COLON);
    
    DataType varType;
    if (match(TokenType::INT32_TYPE)) {
        varType = DataType::INT32;
        advance();
    } else if (match(TokenType::INT64_TYPE)) {
        varType = DataType::INT64;
        advance();
    } else {
        throw std::runtime_error("Expected type");
    }
    
    expect(TokenType::ASSIGN);
    auto varDecl = std::make_unique<VarDeclNode>(name, varType);
    if (match(TokenType::LITERAL)) {
        varDecl->children.push_back(std::make_unique<LiteralNode>(current().value));
        advance();
    }
    expect(TokenType::SEMICOLON);
    return varDecl;
}

std::unique_ptr<FunctionDeclNode> Parser::parseFunctionDecl() {
    expect(TokenType::FUNCTION);
    std::string name = current().value;
    expect(TokenType::IDENTIFIER);
    expect(TokenType::LPAREN);
    
    auto func = std::make_unique<FunctionDeclNode>(name, nullptr);
    
    // Parse parameters
    while (!match(TokenType::RPAREN)) {
        std::string paramName = current().value;
        expect(TokenType::IDENTIFIER);
        
        // Skip type annotation if present (e.g., ": int64")
        if (match(TokenType::COLON)) {
            advance(); // skip colon
            expect(TokenType::IDENTIFIER); // skip type name
        }
        
        func->params.push_back(paramName);
        if (match(TokenType::COMMA)) advance();
    }
    
    expect(TokenType::RPAREN);
    expect(TokenType::LBRACE);
    
    currentDepth++;
    
    while (!match(TokenType::RBRACE)) {
        auto stmt = parseStatement(func.get());
        if (stmt) func->ASTNode::children.push_back(std::move(stmt));
    }
    expect(TokenType::RBRACE);
    currentDepth--;
    return func;
}

std::unique_ptr<ASTNode> Parser::parseFunctionCall() {
    std::string name = current().value;
    expect(TokenType::IDENTIFIER);
    expect(TokenType::LPAREN);
    
    auto call = std::make_unique<FunctionCallNode>(name);
    
    // Parse arguments
    while (!match(TokenType::RPAREN)) {
        if (match(TokenType::IDENTIFIER)) {
            call->args.push_back(std::make_unique<IdentifierNode>(current().value));
            advance();
        } else if (match(TokenType::STRING)) {
            call->args.push_back(std::make_unique<LiteralNode>(current().value));
            advance();
        } else if (match(TokenType::LITERAL)) {
            call->args.push_back(std::make_unique<LiteralNode>(current().value));
            advance();
        }
        if (match(TokenType::COMMA)) {
            advance();
        }
    }
    
    expect(TokenType::RPAREN);
    return call;
}

std::unique_ptr<ASTNode> Parser::parsePrintStmt() {
    expect(TokenType::PRINT);
    expect(TokenType::LPAREN);
    
    auto print = std::make_unique<ASTNode>(NodeType::PRINT_STMT);
    while (!match(TokenType::RPAREN)) {
        if (match(TokenType::STRING)) {
            print->children.push_back(std::make_unique<LiteralNode>(current().value));
            advance();
        } else if (match(TokenType::IDENTIFIER)) {
            print->children.push_back(std::make_unique<IdentifierNode>(current().value));
            advance();
        }
        if (match(TokenType::COMMA)) advance();
    }
    expect(TokenType::RPAREN);
    return print;
}

std::unique_ptr<ASTNode> Parser::parseGoStmt() {
    expect(TokenType::GO);
    auto go = std::make_unique<ASTNode>(NodeType::GO_STMT);
    go->children.push_back(parseFunctionCall());
    return go;
}
