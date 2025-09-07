#include "parser.h"
#include "analyzer.h"
#include "ast_printer.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include "codegen.h"

int main() {
    std::string code0 = R"(
var x: int64 = 10;
print(x)

function test() {

}
    )";
    std::string code1 = R"(
var x: int64 = 0;
function test() {
    var y: int64 = 10;
    print("hello world", x, y)
}
test()
go test()
    )";
    
    std::string code2 = R"(
var small: int32 = 1;
var big1: int64 = 41;
var tiny: int32 = 2;
var big2: int64 = 42;
function level1() {
    var medium: int32 = 10;
    var large: int64 = 100;
    function level2() {
        var mini: int32 = 5;
        print("level1", medium)
        function level3(test) {
            print(big2, mini, medium)
        }
        level3(mini)
    }
    level2()
}
level1()
    )";
    
    Parser parser;
    Analyzer analyzer;
    Codegen codeGen;
    
    std::cout << "=== Parsing Code 0 ===\n";
    auto ast1 = parser.parse(code0);
    analyzer.analyze(ast1.get());
    printAST(ast1.get());
    codeGen.generateProgram(*ast1);
    // Execute the emitted machine code (will call sys_exit after printing Hello, world)
    codeGen.writeProgramToExecutable();


    
    // std::cout << "\n=== Parsing Code 2 ===\n";
    // auto ast2 = parser.parse(code2);
    // analyzer.analyze(ast2.get());
    // printAST(ast2.get());
    
    return 0;
}
