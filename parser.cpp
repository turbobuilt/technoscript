#include "parser.h"
#include <stdexcept>
#include <cctype>
#include <iostream>

void Parser::expect(TokenType t) {
    if (current().type != t) {
        std::string expected = tokenTypeToString(t);
        std::string actual = tokenTypeToString(current().type);
        throw std::runtime_error("Expected " + expected + " but got " + actual + " at position " + std::to_string(pos));
    }
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

std::unique_ptr<FunctionDeclNode> Parser::parse(const std::string& code) {
    std::cout << "DEBUG Parser::parse: Starting parse" << std::endl;
    
    tokens = tokenize(code);
    std::cout << "DEBUG Parser::parse: Tokenized into " << tokens.size() << " tokens" << std::endl;
    
    // Debug: Print all tokens
    for (size_t i = 0; i < tokens.size(); i++) {
        std::cout << "DEBUG Token " << i << ": type=" << (int)tokens[i].type << ", value='" << tokens[i].value << "'" << std::endl;
    }
    
    pos = 0;
    currentDepth = 0;
    auto root = std::make_unique<FunctionDeclNode>("main", nullptr);
    root->depth = 0; // Explicitly set main function depth to 0
    currentLexicalScope = root.get();  // Set initial scope
    
    int iterations = 0;
    size_t lastPos = pos;
    
    while (!match(TokenType::EOF_TOKEN)) {
        std::cout << "DEBUG: Starting iteration " << iterations << ", pos=" << pos << ", token=" << (int)current().type << ", value='" << current().value << "'" << std::endl;
        
        // Prevent infinite loops in parser
        if (++iterations > RobustnessLimits::MAX_PARSER_ITERATIONS) {
            throw std::runtime_error("Parser exceeded maximum iterations (" + 
                                   std::to_string(RobustnessLimits::MAX_PARSER_ITERATIONS) + "), possible infinite loop");
        }
        
        try {
            auto stmt = parseStatement(root.get());
            
            if (stmt) {
                root->ASTNode::children.push_back(std::move(stmt));
            } else {
                // Enhanced error recovery: synchronize to next statement
                if (pos == lastPos) {
                    std::cout << "ERROR: Parser stuck at position " << pos << ", token: " << (int)current().type << " value: '" << current().value << "'" << std::endl;
                    
                    // Try to recover by finding next synchronization point
                    if (!synchronizeToNextStatement()) {
                        throw std::runtime_error("Parser unable to recover from error at position " + std::to_string(pos));
                    }
                    std::cout << "INFO: Parser recovered at position " << pos << std::endl;
                } else {
                    // Position advanced, continue normally
                    if (pos < tokens.size() - 1) advance();
                }
            }
        } catch (const std::runtime_error& e) {
            std::cout << "ERROR: Parsing failed at position " << pos << ": " << e.what() << std::endl;
            
            // Try to recover by finding next synchronization point
            if (!synchronizeToNextStatement()) {
                std::cout << "FATAL: Unable to recover from parsing error" << std::endl;
                throw; // Re-throw the original error
            }
            std::cout << "INFO: Parser recovered from error at position " << pos << std::endl;
        }
        
        lastPos = pos;
    }
    
    std::cout << "DEBUG Parser::parse: Parsing completed successfully" << std::endl;
    return root;
}

std::unique_ptr<ASTNode> Parser::parseStatement(LexicalScopeNode* scope) {
    std::cout << "DEBUG parseStatement: pos=" << pos << ", token type=" << (int)current().type << ", value='" << current().value << "'" << std::endl;
    
    // Skip any unexpected tokens that shouldn't start statements
    while (current().type != TokenType::EOF_TOKEN && 
           current().type != TokenType::VAR &&
           current().type != TokenType::FUNCTION &&
           current().type != TokenType::PRINT &&
           current().type != TokenType::GO &&
           current().type != TokenType::IDENTIFIER &&
           current().type != TokenType::RBRACE) { // Allow } to end blocks naturally
        
        std::cout << "WARNING: Skipping unexpected token at position " << pos << ", type=" << (int)current().type << ", value='" << current().value << "'" << std::endl;
        advance();
        
        if (pos >= tokens.size() - 1) {
            return nullptr;
        }
    }
    
    if (match(TokenType::VAR)) {
        std::cout << "DEBUG parseStatement: parsing VAR" << std::endl;
        return parseVarDecl();
    }
    if (match(TokenType::FUNCTION)) {
        std::cout << "DEBUG parseStatement: parsing FUNCTION" << std::endl;
        return parseFunctionDecl();
    }
    if (match(TokenType::PRINT)) {
        return parsePrintStmt();
    }
    if (match(TokenType::GO)) {
        return parseGoStmt();
    }
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
            
            auto print = std::make_unique<ASTNode>(AstNodeType::PRINT_STMT);
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
    
    // Add variable to current scope's variables map during parsing
    VariableInfo varInfo;
    varInfo.type = varType;
    varInfo.name = name;
    varInfo.definedIn = currentLexicalScope;
    // Set size based on type
    if (varType == DataType::INT32) {
        varInfo.size = 4;
    } else {
        varInfo.size = 8; // INT64 and other types
    }
    currentLexicalScope->variables[name] = varInfo;
    
    return varDecl;
}

std::unique_ptr<FunctionDeclNode> Parser::parseFunctionDecl() {
    expect(TokenType::FUNCTION);
    std::string name = current().value;
    expect(TokenType::IDENTIFIER);
    expect(TokenType::LPAREN);
    
    auto func = std::make_unique<FunctionDeclNode>(name, nullptr);
    
    // Add function closure to current scope's variables map during parsing
    VariableInfo closureVar;
    closureVar.type = DataType::CLOSURE;
    closureVar.name = name;
    closureVar.definedIn = currentLexicalScope;
    closureVar.funcNode = func.get();
    closureVar.size = 8; // Just store function address (8 bytes initially)
    currentLexicalScope->variables[name] = closureVar;
    
    // Parse parameters
    while (!match(TokenType::RPAREN)) {
        std::string paramName = current().value;
        expect(TokenType::IDENTIFIER);
        
        // Skip type annotation if present (e.g., ": int64")
        if (match(TokenType::COLON)) {
            advance(); // skip colon
            // Accept either IDENTIFIER or INT64_TYPE for type names
            if (current().type == TokenType::INT64_TYPE) {
                advance();
            } else {
                expect(TokenType::IDENTIFIER); // For other type names
            }
        }
        
        func->params.push_back(paramName);
        if (match(TokenType::COMMA)) advance();
    }
    
    expect(TokenType::RPAREN);
    expect(TokenType::LBRACE);
    
    // Update scope tracking for function body parsing
    LexicalScopeNode* previousScope = currentLexicalScope;
    currentLexicalScope = func.get();  // Function is a lexical scope
    currentDepth++;
    
    // Add function parameters as variables in the function scope during parsing
    for (const std::string& paramName : func->params) {
        VariableInfo paramVar;
        paramVar.type = DataType::INT64; // Default type for now (should be improved with actual type analysis)
        paramVar.name = paramName;
        paramVar.definedIn = func.get();
        paramVar.size = 8; // Parameters are 8 bytes
        func->variables[paramName] = paramVar;
    }
    
    while (!match(TokenType::RBRACE)) {
        auto stmt = parseStatement(func.get());
        if (stmt) func->ASTNode::children.push_back(std::move(stmt));
    }
    expect(TokenType::RBRACE);
    
    // Restore previous scope
    currentDepth--;
    currentLexicalScope = previousScope;
    
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
    
    auto print = std::make_unique<ASTNode>(AstNodeType::PRINT_STMT);
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

std::unique_ptr<ASTNode> Parser::parseGoStmt() {
    expect(TokenType::GO);
    auto go = std::make_unique<GoStmtNode>();
    
    // Parse the function call that follows 'go'
    auto functionCall = parseFunctionCall();
    if (!functionCall) {
        throw std::runtime_error("Expected function call after 'go' keyword");
    }
    
    // Cast to FunctionCallNode (we know it's a function call from parseFunctionCall)
    auto funcCall = std::unique_ptr<FunctionCallNode>(
        static_cast<FunctionCallNode*>(functionCall.release())
    );
    
    go->functionCall = std::move(funcCall);
    return go;
}

bool Parser::synchronizeToNextStatement() {
    std::cout << "DEBUG: Attempting to synchronize from position " << pos << std::endl;
    
    // Skip tokens until we find a synchronization point
    size_t startPos = pos;
    int safety_counter = 0;
    const int MAX_SYNC_ATTEMPTS = 100; // Prevent infinite loops in recovery
    
    while (pos < tokens.size() - 1 && safety_counter < MAX_SYNC_ATTEMPTS) {
        TokenType currentToken = current().type;
        
        // Synchronization points: statement boundaries
        if (currentToken == TokenType::SEMICOLON) {
            advance(); // Skip the semicolon
            std::cout << "DEBUG: Synchronized at semicolon, new position: " << pos << std::endl;
            return true;
        }
        else if (currentToken == TokenType::RBRACE) {
            // End of block - we can start fresh from here
            advance(); // Skip the }
            std::cout << "DEBUG: Synchronized at end of block, new position: " << pos << std::endl;
            return true;
        }
        else if (currentToken == TokenType::FUNCTION || 
                 currentToken == TokenType::VAR) {
            // Start of new statement - don't skip these tokens
            std::cout << "DEBUG: Synchronized at statement start, position: " << pos << std::endl;
            return true;
        }
        else if (currentToken == TokenType::EOF_TOKEN) {
            std::cout << "DEBUG: Reached EOF during synchronization" << std::endl;
            return false; // Can't recover, we're at the end
        }
        
        advance();
        safety_counter++;
    }
    
    // If we couldn't find a synchronization point
    if (safety_counter >= MAX_SYNC_ATTEMPTS) {
        std::cout << "ERROR: Exceeded maximum synchronization attempts" << std::endl;
        return false;
    }
    
    if (pos == startPos) {
        std::cout << "ERROR: No progress made during synchronization" << std::endl;
        return false;
    }
    
    std::cout << "DEBUG: Synchronization completed, advanced from " << startPos << " to " << pos << std::endl;
    return true;
}

std::string Parser::tokenTypeToString(TokenType type) {
    switch (type) {
        case TokenType::VAR: return "VAR";
        case TokenType::FUNCTION: return "FUNCTION";
        case TokenType::GO: return "GO";
        case TokenType::IDENTIFIER: return "IDENTIFIER";
        case TokenType::INT32_TYPE: return "INT32_TYPE";
        case TokenType::INT64_TYPE: return "INT64_TYPE";
        case TokenType::LITERAL: return "LITERAL";
        case TokenType::ASSIGN: return "ASSIGN (=)";
        case TokenType::SEMICOLON: return "SEMICOLON (;)";
        case TokenType::LPAREN: return "LPAREN (()";
        case TokenType::RPAREN: return "RPAREN ())";
        case TokenType::LBRACE: return "LBRACE ({)";
        case TokenType::RBRACE: return "RBRACE (})";
        case TokenType::COLON: return "COLON (:)";
        case TokenType::COMMA: return "COMMA (,)";
        case TokenType::STRING: return "STRING";
        case TokenType::PRINT: return "PRINT";
        case TokenType::DOT: return "DOT (.)";
        case TokenType::EOF_TOKEN: return "EOF";
        default: return "UNKNOWN";
    }
}
