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
            else if (word == "setTimeout") result.emplace_back(TokenType::SETTIMEOUT);
            else if (word == "async") result.emplace_back(TokenType::ASYNC);
            else if (word == "await") result.emplace_back(TokenType::AWAIT);
            else if (word == "promise") result.emplace_back(TokenType::PROMISE);
            else if (word == "sleep") result.emplace_back(TokenType::SLEEP);
            else if (word == "for") result.emplace_back(TokenType::FOR);
            else if (word == "let") result.emplace_back(TokenType::LET);
            else if (word == "class") result.emplace_back(TokenType::CLASS);
            else if (word == "new") result.emplace_back(TokenType::NEW);
            else if (word == "this") result.emplace_back(TokenType::THIS);
            else if (word == "extends") result.emplace_back(TokenType::EXTENDS);
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
            switch (code[i]) {
                case '=': result.emplace_back(TokenType::ASSIGN); i++; break;
                case ';': result.emplace_back(TokenType::SEMICOLON); i++; break;
                case '(': result.emplace_back(TokenType::LPAREN); i++; break;
                case ')': result.emplace_back(TokenType::RPAREN); i++; break;
                case '{': result.emplace_back(TokenType::LBRACE); i++; break;
                case '}': result.emplace_back(TokenType::RBRACE); i++; break;
                case ':': result.emplace_back(TokenType::COLON); i++; break;
                case ',': result.emplace_back(TokenType::COMMA); i++; break;
                case '.': result.emplace_back(TokenType::DOT); i++; break;
                case '<': result.emplace_back(TokenType::LESS_THAN); i++; break;
                case '+':
                    if (i + 1 < code.length() && code[i + 1] == '+') {
                        result.emplace_back(TokenType::PLUS_PLUS);
                        i += 2;
                    } else {
                        i++; // Skip unrecognized single '+'
                    }
                    break;
                default: i++; break; // Skip unrecognized characters
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
    currentFunctionScope = root.get(); // Main is also the initial function scope
    
    // Register the main function in the function registry
    functionRegistry.push_back(root.get());
    
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
           current().type != TokenType::ASYNC &&  // Add ASYNC token
           current().type != TokenType::PRINT &&
           current().type != TokenType::SETTIMEOUT &&
           current().type != TokenType::GO &&
           current().type != TokenType::FOR &&     // Add FOR token
           current().type != TokenType::LET &&     // Add LET token
           current().type != TokenType::LBRACE &&  // Add LBRACE for block statements
           current().type != TokenType::CLASS &&   // Add CLASS token
           current().type != TokenType::IDENTIFIER &&
           current().type != TokenType::THIS &&    // Add THIS token for method calls like this.method()
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
    if (match(TokenType::CLASS)) {
        std::cout << "DEBUG parseStatement: parsing CLASS" << std::endl;
        return parseClassDecl();
    }
    if (match(TokenType::LET)) {
        std::cout << "DEBUG parseStatement: parsing LET" << std::endl;
        return parseLetDecl();
    }
    if (match(TokenType::FOR)) {
        std::cout << "DEBUG parseStatement: parsing FOR" << std::endl;
        return parseForStmt();
    }
    if (match(TokenType::LBRACE)) {
        std::cout << "DEBUG parseStatement: parsing BLOCK" << std::endl;
        return parseBlockStmt();
    }
    if (match(TokenType::ASYNC)) {
        std::cout << "DEBUG parseStatement: parsing ASYNC FUNCTION" << std::endl;
        std::cout << "DEBUG: Before advance, pos=" << pos << ", token type=" << (int)current().type << std::endl;
        advance(); // consume ASYNC token
        std::cout << "DEBUG: After advance, pos=" << pos << ", token type=" << (int)current().type << std::endl;
        if (match(TokenType::FUNCTION)) {
            std::cout << "DEBUG parseStatement: found FUNCTION after ASYNC" << std::endl;
            return parseFunctionDecl(); // Don't advance again, parseFunctionDecl will handle it
        } else {
            std::cout << "DEBUG: Expected FUNCTION but found token type " << (int)current().type << " at pos " << pos << std::endl;
            throw std::runtime_error("Expected FUNCTION after ASYNC");
        }
    }
    if (match(TokenType::FUNCTION)) {
        std::cout << "DEBUG parseStatement: parsing FUNCTION" << std::endl;
        return parseFunctionDecl();
    }
    if (match(TokenType::PRINT)) {
        return parsePrintStmt();
    }
    if (match(TokenType::SETTIMEOUT)) {
        return parseSetTimeoutStmt();
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
        }
        // Check for member access (obj.member or obj.member = value or obj.method())
        else if (pos + 1 < tokens.size() && tokens[pos + 1].type == TokenType::DOT) {
            std::string objName = current().value;
            advance(); // consume identifier
            expect(TokenType::DOT);
            
            std::string memberName = current().value;
            expect(TokenType::IDENTIFIER);
            
            // Check if this is a method call (obj.method(...))
            if (match(TokenType::LPAREN)) {
                advance(); // consume (
                
                auto methodCall = std::make_unique<MethodCallNode>(memberName);
                methodCall->object = std::make_unique<IdentifierNode>(objName);
                
                // Parse arguments
                if (!match(TokenType::RPAREN)) {
                    do {
                        if (match(TokenType::LITERAL)) {
                            methodCall->args.push_back(std::make_unique<LiteralNode>(current().value));
                            advance();
                        } else if (match(TokenType::IDENTIFIER)) {
                            methodCall->args.push_back(std::make_unique<IdentifierNode>(current().value));
                            advance();
                        } else if (match(TokenType::THIS)) {
                            methodCall->args.push_back(std::make_unique<ThisNode>());
                            advance();
                        } else {
                            throw std::runtime_error("Expected argument in method call");
                        }
                        
                        if (match(TokenType::COMMA)) {
                            advance();
                        } else {
                            break;
                        }
                    } while (true);
                }
                
                expect(TokenType::RPAREN);
                expect(TokenType::SEMICOLON);
                return methodCall;
            }
            // Check if this is an assignment
            else if (match(TokenType::ASSIGN)) {
                advance(); // consume =
                
                auto memberAssign = std::make_unique<MemberAssignNode>();
                auto memberAccess = std::make_unique<MemberAccessNode>(memberName);
                memberAccess->object = std::make_unique<IdentifierNode>(objName);
                memberAssign->member = std::move(memberAccess);
                
                // Parse the value being assigned
                if (match(TokenType::LITERAL)) {
                    memberAssign->value = std::make_unique<LiteralNode>(current().value);
                    advance();
                } else if (match(TokenType::IDENTIFIER)) {
                    memberAssign->value = std::make_unique<IdentifierNode>(current().value);
                    advance();
                } else if (match(TokenType::THIS)) {
                    memberAssign->value = std::make_unique<ThisNode>();
                    advance();
                } else {
                    throw std::runtime_error("Expected value after assignment");
                }
                
                expect(TokenType::SEMICOLON);
                return memberAssign;
            } else {
                // Just member access (for reading)
                auto memberAccess = std::make_unique<MemberAccessNode>(memberName);
                memberAccess->object = std::make_unique<IdentifierNode>(objName);
                return memberAccess;
            }
        } else {
            // Just return an identifier node
            auto identifier = std::make_unique<IdentifierNode>(current().value);
            advance();
            return identifier;
        }
    }
    // Handle 'this' keyword
    else if (match(TokenType::THIS)) {
        advance();
        
        // Check for 'this.member' access
        if (match(TokenType::DOT)) {
            advance(); // consume '.'
            std::string memberName = current().value;
            expect(TokenType::IDENTIFIER);
            
            std::cout << "DEBUG: Parsing this." << memberName << ", next token type: " << (int)current().type << std::endl;
            
            // Check if this is a method call (this.method(...))
            if (match(TokenType::LPAREN)) {
                std::cout << "DEBUG: Detected method call this." << memberName << "()" << std::endl;
                advance(); // consume (
                
                auto methodCall = std::make_unique<MethodCallNode>(memberName);
                methodCall->object = std::make_unique<ThisNode>();
                
                // Parse arguments
                if (!match(TokenType::RPAREN)) {
                    do {
                        if (match(TokenType::LITERAL)) {
                            methodCall->args.push_back(std::make_unique<LiteralNode>(current().value));
                            advance();
                        } else if (match(TokenType::IDENTIFIER)) {
                            methodCall->args.push_back(std::make_unique<IdentifierNode>(current().value));
                            advance();
                        } else if (match(TokenType::THIS)) {
                            methodCall->args.push_back(std::make_unique<ThisNode>());
                            advance();
                        } else {
                            throw std::runtime_error("Expected argument in method call");
                        }
                        
                        if (match(TokenType::COMMA)) {
                            advance();
                        } else {
                            break;
                        }
                    } while (true);
                }
                
                expect(TokenType::RPAREN);
                expect(TokenType::SEMICOLON);
                std::cout << "DEBUG: Successfully parsed this." << memberName << "() method call" << std::endl;
                return methodCall;
            } else {
                // Create member access with 'this' as the object
                std::cout << "DEBUG: Creating member access for this." << memberName << std::endl;
                auto memberAccess = std::make_unique<MemberAccessNode>(memberName);
                memberAccess->object = std::make_unique<ThisNode>();
                return memberAccess;
            }
        } else {
            // Just 'this' by itself
            return std::make_unique<ThisNode>();
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
    std::string customTypeName; // For object types
    
    if (match(TokenType::INT32_TYPE)) {
        varType = DataType::INT32;
        advance();
    } else if (match(TokenType::INT64_TYPE)) {
        varType = DataType::INT64;
        advance();
    } else if (match(TokenType::IDENTIFIER)) {
        // Custom type (class name)
        varType = DataType::OBJECT;
        customTypeName = current().value;
        advance();
    } else {
        throw std::runtime_error("Expected type");
    }
    
    expect(TokenType::ASSIGN);
    auto varDecl = std::make_unique<VarDeclNode>(name, varType, customTypeName);
    
    if (match(TokenType::NEW)) {
        // Parse new expression
        advance(); // consume NEW
        std::string className = current().value;
        expect(TokenType::IDENTIFIER);
        expect(TokenType::LPAREN);
        expect(TokenType::RPAREN); // For now, no constructor arguments
        
        auto newExpr = std::make_unique<NewExprNode>(className);
        varDecl->children.push_back(std::move(newExpr));
    } else if (match(TokenType::LITERAL)) {
        varDecl->children.push_back(std::make_unique<LiteralNode>(current().value));
        advance();
    } else if (match(TokenType::AWAIT)) {
        std::cout << "DEBUG parseVarDecl: parsing AWAIT expression" << std::endl;
        advance(); // consume AWAIT token
        
        // Create an AWAIT_EXPR node
        auto awaitExpr = std::make_unique<AwaitExprNode>();
        
        if (match(TokenType::SLEEP)) {
            std::cout << "DEBUG parseVarDecl: parsing SLEEP call" << std::endl;
            advance(); // consume SLEEP token
            expect(TokenType::LPAREN);
            
            // Create a SLEEP_CALL node
            auto sleepCall = std::make_unique<SleepCallNode>();
            
            if (match(TokenType::LITERAL)) {
                sleepCall->children.push_back(std::make_unique<LiteralNode>(current().value));
                advance();
            } else {
                throw std::runtime_error("Expected literal argument for sleep()");
            }
            
            expect(TokenType::RPAREN);
            awaitExpr->children.push_back(std::move(sleepCall));
        } else {
            throw std::runtime_error("Expected function call after await");
        }
        
        varDecl->children.push_back(std::move(awaitExpr));
    } else if (match(TokenType::IDENTIFIER)) {
        std::cout << "DEBUG parseVarDecl: parsing identifier/function call" << std::endl;
        varDecl->children.push_back(std::make_unique<IdentifierNode>(current().value));
        advance();
    } else {
        throw std::runtime_error("Expected literal, await expression, or identifier after assignment");
    }
    
    expect(TokenType::SEMICOLON);
    
    // Add variable to appropriate scope based on declaration type
    // var: function-scoped (use current function scope)
    // let: block-scoped (use current lexical scope)
    VariableInfo varInfo;
    varInfo.type = varType;
    varInfo.name = name;
    
    // For var declarations, use the current function scope
    if (!currentFunctionScope) {
        throw std::runtime_error("var declaration outside of function scope");
    }
    
    varInfo.definedIn = currentFunctionScope;
    
    // Set size based on type
    if (varType == DataType::INT32) {
        varInfo.size = 4;
    } else if (varType == DataType::OBJECT) {
        varInfo.size = 8; // Pointer to heap-allocated object
    } else {
        varInfo.size = 8; // INT64 and other types
    }
    
    std::cout << "DEBUG parseVarDecl: Adding variable '" << name << "' to function scope at depth " << currentFunctionScope->depth << std::endl;
    currentFunctionScope->variables[name] = varInfo;
    
    return varDecl;
}

std::unique_ptr<LetDeclNode> Parser::parseLetDecl() {
    expect(TokenType::LET);
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
    auto letDecl = std::make_unique<LetDeclNode>(name, varType);
    
    if (match(TokenType::LITERAL)) {
        letDecl->children.push_back(std::make_unique<LiteralNode>(current().value));
        advance();
    } else if (match(TokenType::IDENTIFIER)) {
        letDecl->children.push_back(std::make_unique<IdentifierNode>(current().value));
        advance();
    } else {
        throw std::runtime_error("Expected literal or identifier after assignment");
    }
    
    // Note: Let declarations don't need semicolons when used in for loops
    // The caller (parseForStmt) will handle this appropriately
    
    // Add variable to current lexical scope (block-scoped for let declarations)
    VariableInfo varInfo;
    varInfo.type = varType;
    varInfo.name = name;
    varInfo.definedIn = currentLexicalScope;  // let is block-scoped
    
    // Set size based on type
    if (varType == DataType::INT32) {
        varInfo.size = 4;
    } else {
        varInfo.size = 8; // INT64 and other types
    }

    std::cout << "DEBUG parseLetDecl: Adding variable '" << name << "' to block scope at depth " << (currentLexicalScope ? currentLexicalScope->depth : -1) << std::endl;
    currentLexicalScope->variables[name] = varInfo;    return letDecl;
}

std::unique_ptr<ASTNode> Parser::parseExpression() {
    // Simple expression parser for basic operations
    // For now, we'll handle:
    // - Comparisons: identifier < literal
    // - Increment: ++identifier
    // - Identifiers and literals
    
    if (match(TokenType::PLUS_PLUS)) {
        advance(); // consume ++
        if (match(TokenType::IDENTIFIER)) {
            // Create a unary expression node for ++i
            auto increment = std::make_unique<UnaryExprNode>("++");
            increment->operand = std::make_unique<IdentifierNode>(current().value);
            advance();
            return increment;
        } else {
            throw std::runtime_error("Expected identifier after ++");
        }
    } else if (match(TokenType::IDENTIFIER)) {
        std::string leftSide = current().value;
        advance();
        
        // Check if this is a comparison
        if (match(TokenType::LESS_THAN)) {
            advance(); // consume <
            
            // Create a binary expression node for comparison
            std::cout << "DEBUG parseExpression: Creating binary expression for " << leftSide << " < ..." << std::endl;
            auto comparison = std::make_unique<BinaryExprNode>("<");
            comparison->left = std::make_unique<IdentifierNode>(leftSide);
            
            if (match(TokenType::LITERAL)) {
                comparison->right = std::make_unique<LiteralNode>(current().value);
                advance();
            } else if (match(TokenType::IDENTIFIER)) {
                comparison->right = std::make_unique<IdentifierNode>(current().value);
                advance();
            } else {
                throw std::runtime_error("Expected literal or identifier after <");
            }
            
            return comparison;
        } else {
            // Just return the identifier
            return std::make_unique<IdentifierNode>(leftSide);
        }
    } else if (match(TokenType::LITERAL)) {
        auto literal = std::make_unique<LiteralNode>(current().value);
        advance();
        return literal;
    } else {
        throw std::runtime_error("Expected expression");
    }
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
    closureVar.size = 16; // function_address (8) + size (8) - scope pointers added later by analyzer
    currentLexicalScope->variables[name] = closureVar;
    
    // Register this function for early code generation
    functionRegistry.push_back(func.get());
    
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
    LexicalScopeNode* previousLexicalScope = currentLexicalScope;
    LexicalScopeNode* previousFunctionScope = currentFunctionScope;
    currentLexicalScope = func.get();  // Function is a lexical scope
    currentFunctionScope = func.get(); // Function is also a function scope
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
    
    // Restore previous scopes
    currentDepth--;
    currentLexicalScope = previousLexicalScope;
    currentFunctionScope = previousFunctionScope;
    
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
        } else if (match(TokenType::THIS)) {
            // Check for 'this.member' access
            advance(); // consume 'this'
            if (match(TokenType::DOT)) {
                advance(); // consume '.'
                std::string memberName = current().value;
                expect(TokenType::IDENTIFIER);
                
                auto memberAccess = std::make_unique<MemberAccessNode>(memberName);
                memberAccess->object = std::make_unique<ThisNode>();
                print->children.push_back(std::move(memberAccess));
            } else {
                // Just 'this' by itself
                print->children.push_back(std::make_unique<ThisNode>());
            }
        } else if (match(TokenType::IDENTIFIER)) {
            // Check for member access (obj.member)
            if (pos + 1 < tokens.size() && tokens[pos + 1].type == TokenType::DOT) {
                std::string objName = current().value;
                advance(); // consume identifier
                expect(TokenType::DOT);
                
                std::string memberName = current().value;
                expect(TokenType::IDENTIFIER);
                
                auto memberAccess = std::make_unique<MemberAccessNode>(memberName);
                memberAccess->object = std::make_unique<IdentifierNode>(objName);
                print->children.push_back(std::move(memberAccess));
            } else {
                print->children.push_back(std::make_unique<IdentifierNode>(current().value));
                advance();
            }
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

std::unique_ptr<ASTNode> Parser::parseSetTimeoutStmt() {
    expect(TokenType::SETTIMEOUT);
    expect(TokenType::LPAREN);
    
    auto setTimeout = std::make_unique<SetTimeoutStmtNode>();
    
    // First parameter: function name (identifier)
    if (!match(TokenType::IDENTIFIER)) {
        throw std::runtime_error("Expected function name as first parameter to setTimeout");
    }
    setTimeout->functionName = std::make_unique<IdentifierNode>(current().value);
    advance();
    
    expect(TokenType::COMMA);
    
    // Second parameter: delay in milliseconds (literal)
    if (!match(TokenType::LITERAL)) {
        throw std::runtime_error("Expected delay in milliseconds as second parameter to setTimeout");
    }
    setTimeout->delay = std::make_unique<LiteralNode>(current().value);
    advance();
    
    expect(TokenType::RPAREN);
    expect(TokenType::SEMICOLON);
    
    return setTimeout;
}

std::unique_ptr<ForStmtNode> Parser::parseForStmt() {
    expect(TokenType::FOR);
    expect(TokenType::LPAREN);
    
    // Create a new for loop scope
    auto forStmt = std::make_unique<ForStmtNode>(currentLexicalScope, currentDepth + 1);
    
    // Update scope tracking for the for loop body parsing
    LexicalScopeNode* previousScope = currentLexicalScope;
    currentLexicalScope = forStmt.get();  // For loop is a lexical scope
    currentDepth++;
    
    // Parse initialization (e.g., let i: int64 = 0)
    if (!match(TokenType::SEMICOLON)) {
        if (match(TokenType::LET)) {
            forStmt->init = parseLetDecl();
        } else {
            throw std::runtime_error("Expected let declaration in for loop initialization");
        }
    }
    expect(TokenType::SEMICOLON);
    
    // Parse condition (e.g., i < 2)
    if (!match(TokenType::SEMICOLON)) {
        forStmt->condition = parseExpression();
    }
    expect(TokenType::SEMICOLON);
    
    // Parse update (e.g., ++i)
    if (!match(TokenType::RPAREN)) {
        forStmt->update = parseExpression();
    }
    expect(TokenType::RPAREN);
    
    expect(TokenType::LBRACE);
    
    // Parse body statements
    while (!match(TokenType::RBRACE)) {
        auto stmt = parseStatement(forStmt.get());
        if (stmt) {
            forStmt->ASTNode::children.push_back(std::move(stmt));
        }
    }
    expect(TokenType::RBRACE);
    
    // Restore previous scope
    currentDepth--;
    currentLexicalScope = previousScope;
    
    return forStmt;
}

std::unique_ptr<BlockStmtNode> Parser::parseBlockStmt() {
    std::cout << "DEBUG parseBlockStmt: Starting to parse block statement" << std::endl;
    expect(TokenType::LBRACE);
    
    // Create a new block scope
    auto blockStmt = std::make_unique<BlockStmtNode>(currentLexicalScope, currentDepth + 1);
    
    // Update scope tracking for the block body parsing
    LexicalScopeNode* previousScope = currentLexicalScope;
    currentLexicalScope = blockStmt.get();  // Block is a lexical scope
    currentDepth++;
    
    std::cout << "DEBUG parseBlockStmt: Entering block scope, depth=" << currentDepth << std::endl;
    
    // Parse body statements
    while (!match(TokenType::RBRACE) && current().type != TokenType::EOF_TOKEN) {
        auto stmt = parseStatement(blockStmt.get());
        if (stmt) {
            std::cout << "DEBUG parseBlockStmt: Adding statement to block" << std::endl;
            blockStmt->ASTNode::children.push_back(std::move(stmt));
        }
    }
    expect(TokenType::RBRACE);
    
    std::cout << "DEBUG parseBlockStmt: Exiting block scope, depth=" << currentDepth << std::endl;
    
    // Restore previous scope
    currentDepth--;
    currentLexicalScope = previousScope;
    
    return blockStmt;
}

std::unique_ptr<ClassDeclNode> Parser::parseClassDecl() {
    expect(TokenType::CLASS);
    std::string className = current().value;
    expect(TokenType::IDENTIFIER);
    
    // Check for duplicate class names
    if (classRegistry.find(className) != classRegistry.end()) {
        throw std::runtime_error("Duplicate class definition: class '" + className + "' is already defined");
    }
    
    auto classDecl = std::make_unique<ClassDeclNode>(className);
    
    // Parse inheritance (optional): class Dog extends Animal, Mammal
    if (match(TokenType::EXTENDS)) {
        advance(); // consume 'extends'
        
        // Parse parent class names
        do {
            if (!match(TokenType::IDENTIFIER)) {
                throw std::runtime_error("Expected parent class name after 'extends'");
            }
            std::string parentName = current().value;
            classDecl->parentClassNames.push_back(parentName);
            std::cout << "DEBUG parseClassDecl: Class '" << className << "' inherits from '" << parentName << "'" << std::endl;
            advance();
            
            // Check for comma (more parents)
            if (match(TokenType::COMMA)) {
                advance();
            } else {
                break;
            }
        } while (true);
    }
    
    expect(TokenType::LBRACE);
    
    // Parse class body (fields and methods)
    while (!match(TokenType::RBRACE) && current().type != TokenType::EOF_TOKEN) {
        // Check if this is a method or a field
        // Method: identifier followed by '(' (with or without 'function' keyword)
        // Field: identifier followed by ':'
        
        bool isFunction = match(TokenType::FUNCTION);
        if (isFunction) {
            advance(); // consume 'function'
        }
        
        std::string memberName = current().value;
        expect(TokenType::IDENTIFIER);
        
        // Check next token to determine if this is a method or field
        bool isMethod = match(TokenType::LPAREN);
        
        if (isMethod || isFunction) {
            // Parse method
            std::string methodName = memberName;
            
            std::cout << "DEBUG parseClassDecl: Parsing method '" << methodName << "' in class '" << className << "'" << std::endl;
            
            // Create a FunctionDeclNode for the method
            auto method = std::make_unique<FunctionDeclNode>(methodName, currentLexicalScope);
            method->depth = currentDepth + 1; // Methods are one level deeper than the class scope
            method->isMethod = true;          // Mark this as a method
            method->owningClass = classDecl.get(); // Set the owning class
            
            expect(TokenType::LPAREN);
            
            // Parse parameters
            if (!match(TokenType::RPAREN)) {
                do {
                    std::string paramName = current().value;
                    expect(TokenType::IDENTIFIER);
                    expect(TokenType::COLON);
                    
                    DataType paramType;
                    if (match(TokenType::INT32_TYPE)) {
                        paramType = DataType::INT32;
                        advance();
                    } else if (match(TokenType::INT64_TYPE)) {
                        paramType = DataType::INT64;
                        advance();
                    } else {
                        throw std::runtime_error("Expected type for parameter in method");
                    }
                    
                    method->params.push_back(paramName);
                    
                    // Add to paramsInfo (will be properly set up during analysis)
                    VariableInfo paramInfo;
                    paramInfo.type = paramType;
                    paramInfo.name = paramName;
                    paramInfo.size = (paramType == DataType::INT32) ? 4 : 8;
                    method->paramsInfo.push_back(paramInfo);
                    
                    if (match(TokenType::COMMA)) {
                        advance();
                    } else {
                        break;
                    }
                } while (true);
            }
            
            expect(TokenType::RPAREN);
            
            // Optional return type
            if (match(TokenType::COLON)) {
                advance();
                if (match(TokenType::INT32_TYPE) || match(TokenType::INT64_TYPE)) {
                    advance(); // consume return type (we'll handle this properly later)
                }
            }
            
            // Parse method body
            expect(TokenType::LBRACE);
            
            // Save current scope and set method as current scope
            LexicalScopeNode* previousScope = currentLexicalScope;
            LexicalScopeNode* previousFunctionScope = currentFunctionScope;
            currentLexicalScope = method.get();
            currentFunctionScope = method.get();
            currentDepth++;
            
            // Parse statements in method body
            while (!match(TokenType::RBRACE) && current().type != TokenType::EOF_TOKEN) {
                auto stmt = parseStatement(method.get());
                if (stmt) {
                    method->children.push_back(std::move(stmt));
                }
            }
            
            expect(TokenType::RBRACE);
            
            // Restore previous scope
            currentDepth--;
            currentLexicalScope = previousScope;
            currentFunctionScope = previousFunctionScope;
            
            std::cout << "DEBUG parseClassDecl: Finished parsing method '" << methodName << "'" << std::endl;
            
            // Register this method for early code generation
            functionRegistry.push_back(method.get());
            
            // Add method to class
            classDecl->methods[methodName] = std::move(method);
            
        } else {
            // Parse field
            std::string fieldName = memberName; // Use the memberName we already parsed
            expect(TokenType::COLON);
            
            DataType fieldType;
            int fieldSize = 8; // default size
            
            if (match(TokenType::INT32_TYPE)) {
                fieldType = DataType::INT32;
                fieldSize = 4;
                advance();
            } else if (match(TokenType::INT64_TYPE)) {
                fieldType = DataType::INT64;
                fieldSize = 8;
                advance();
            } else {
                throw std::runtime_error("Expected type for field");
            }
            
            // Create VariableInfo for the field
            VariableInfo fieldInfo;
            fieldInfo.type = fieldType;
            fieldInfo.name = fieldName;
            fieldInfo.size = fieldSize;
            fieldInfo.offset = 0; // Will be set during packing/layout
            
            classDecl->fields[fieldName] = fieldInfo;
            expect(TokenType::SEMICOLON);
        }
    }
    
    expect(TokenType::RBRACE);
    
    // Don't pack here - the analyzer will do it after resolving inheritance and building method layout
    
    // Register the class in the global registry
    classRegistry[className] = classDecl.get();
    
    std::cout << "DEBUG parseClassDecl: Parsed class '" << className << "' with " 
              << classDecl->fields.size() << " fields and " << classDecl->methods.size() 
              << " methods" << std::endl;
    return classDecl;
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
        case TokenType::SETTIMEOUT: return "SETTIMEOUT";
        case TokenType::DOT: return "DOT (.)";
        case TokenType::FOR: return "FOR";
        case TokenType::LET: return "LET";
        case TokenType::LESS_THAN: return "LESS_THAN (<)";
        case TokenType::PLUS_PLUS: return "PLUS_PLUS (++)";
        case TokenType::CLASS: return "CLASS";
        case TokenType::NEW: return "NEW";
        case TokenType::THIS: return "THIS";
        case TokenType::EXTENDS: return "EXTENDS";
        case TokenType::EOF_TOKEN: return "EOF";
        default: return "UNKNOWN";
    }
}
