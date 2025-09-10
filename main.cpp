#include "parser.h"
#include "analyzer.h"
#include "ast_printer.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include "codegen.h"

int main() {
    std::string code = R"(
var global_a: int64 = 100;
var global_b: int64 = 200;

function outer(param_x) {
    var outer_var: int64 = 300;
    
    function middle(param_y) {
        var middle_var: int64 = 400;
        
        function inner(param_z) {
            print(param_z)
            print(param_y)
            print(param_x)
            print(middle_var)
            print(outer_var)
            print(global_a)
            print(global_b)
        }
        
        inner(middle_var)
        print(param_y)
    }
    
    middle(outer_var)
    print(param_x)
}

outer(global_a)
    )";

    std::string code_simple = R"(
var x: int64 = 10;
print(x)
function test(a) {
 print(a)
}
test(x)
)";
    
    Parser parser;
    Analyzer analyzer;
    Codegen codeGen;
    
    
    std::cout << "=== Testing complex nested closures with multiple scope levels ===\n";
    auto ast5 = parser.parse(code_simple);
    analyzer.analyze(ast5.get());
    printAST(ast5.get());
    
    // Debug: Check what address print_int64 actually has
    uint64_t actual_print_addr = reinterpret_cast<uint64_t>(print_int64);
    std::cout << "DEBUG: Actual print_int64 address: 0x" << std::hex << actual_print_addr << std::dec << std::endl;
    
    Codegen codeGen5;
    codeGen5.generateProgram(*ast5);
    codeGen5.writeProgramToExecutable();
    
    return 0;
}
