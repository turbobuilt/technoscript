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
    
    std::string code_robust_test = R"(
var x: int64 = 42;
var y: int64 = 100;
function helper(param) {
    print(param)
}
helper(x)
print(y)
helper(y)
print(x)
    )";
    
    std::cout << "=== Testing robust function calling - variables should be preserved ===\n";
    auto ast5 = parser.parse(code_robust_test);
    analyzer.analyze(ast5.get());
    printAST(ast5.get());
    Codegen codeGen5;
    codeGen5.generateProgram(*ast5);
    codeGen5.writeProgramToExecutable();
    
    return 0;
}
