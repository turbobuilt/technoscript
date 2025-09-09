#include "parser.h"
#include "analyzer.h"
#include "ast_printer.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include "codegen.h"

int main() {
    std::string code = R"(
var a: int64 = 10;
var b: int64 = 20;
function add(x) {
    print(x)
    print(b)
}
add(a)
    )";
    
    Parser parser;
    Analyzer analyzer;
    Codegen codeGen;
    
    
    std::cout << "=== Testing robust function calling - variables should be preserved ===\n";
    auto ast5 = parser.parse(code);
    analyzer.analyze(ast5.get());
    printAST(ast5.get());
    Codegen codeGen5;
    codeGen5.generateProgram(*ast5);
    codeGen5.writeProgramToExecutable();
    
    return 0;
}
