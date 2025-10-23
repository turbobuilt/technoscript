#include "parser.h"
#include <sstream>

void Parser::validateSliceSyntax(const std::string& memberName) {
    if (match(TokenType::LBRACKET)) {
        std::stringstream error;
        error << "Invalid slice syntax at '" << memberName << "'. ";
        
        // Common error cases
        if (!matchNext(TokenType::COLON) && !matchNext(TokenType::LITERAL) && !matchNext(TokenType::IDENTIFIER)) {
            error << "Expected number, variable name, or ':' after '['";
        }
        else if (matchNext(TokenType::COLON) && !matchOffset(2, TokenType::COLON) && 
                 !matchOffset(2, TokenType::LITERAL) && !matchOffset(2, TokenType::IDENTIFIER) &&
                 !matchOffset(2, TokenType::RBRACKET)) {
            error << "Expected number, variable name, or ']' after ':'";
        }
        else if (matchNext(TokenType::IDENTIFIER) && !matchOffset(2, TokenType::COLON) && 
                 !matchOffset(2, TokenType::COMMA) && !matchOffset(2, TokenType::RBRACKET)) {
            error << "Expected ':', ',' or ']' after variable name";
        }
        
        throw std::runtime_error(error.str());
    }
}