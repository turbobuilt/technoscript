#include "parser.h"
#include "analyzer.h"
#include "ast_printer.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include "codegen.h"

int main() {
    std::string code_simple = R"(
var a: int64 = 10;
var b: int64 = 20;
function add(x, y) {
    print(x)
    print(y)
}
add(a, b)
    )";
    
    std::string code_literal = R"(
function test(a, b, c) {
    print(a)
    print(b) 
    print(c)
}
test(100, 200, 300)
    )";
    
    Parser parser;
    Analyzer analyzer;
    Codegen codeGen;
    
    std::cout << "=== Testing function call with literal arguments ===\n";
    auto ast2 = parser.parse(code_literal);
    analyzer.analyze(ast2.get());
    printAST(ast2.get());
    Codegen codeGen2;
    codeGen2.generateProgram(*ast2);
    codeGen2.writeProgramToExecutable();
    
    return 0;
}
