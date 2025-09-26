#include "parser.h"
#include <iostream>

int main() {
    Parser parser;
    std::string code = "function test() { var x: int64 = 2; print(x); } test()";
    
    std::cout << "Input code: '" << code << "'" << std::endl;
    std::cout << "Code length: " << code.length() << std::endl;
    
    // Make tokenize public temporarily or add a debug method
    auto tokens = parser.tokenize(code);
    
    std::cout << "Tokenized " << tokens.size() << " tokens:" << std::endl;
    for (size_t i = 0; i < tokens.size(); i++) {
        std::cout << "Token " << i << ": type=" << static_cast<int>(tokens[i].type);
        if (!tokens[i].value.empty()) {
            std::cout << ", value='" << tokens[i].value << "'";
        }
        std::cout << std::endl;
    }
    
    return 0;
}