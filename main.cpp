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
    
    std::string code_closure = R"(
var x: int64 = 42;
function inner() {
    print(x)
}
inner()
    )";
    
    std::string code_closure_with_params = R"(
var x: int64 = 42;
function inner(y) {
    print(x)
    print(y)
}
inner(100)
    )";
    
    std::cout << "=== Testing closure with params and parent scope access ===\n";
    auto ast4 = parser.parse(code_closure_with_params);
    analyzer.analyze(ast4.get());
    printAST(ast4.get());
    Codegen codeGen4;
    codeGen4.generateProgram(*ast4);
    codeGen4.writeProgramToExecutable();
    
    return 0;
}
