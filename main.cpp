#include "parser.h"
#include "analyzer.h"
#include "ast_printer.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include "codegen.h"

int main(int argc, char* argv[]) {
    std::cout << "DEBUG: Program started" << std::endl;
    std::cout.flush();
    
    std::string code;
    std::cout << "DEBUG: About to process command line arguments" << std::endl;
    
    if (argc > 1) {
        std::cout << "DEBUG: Reading from file: " << argv[1] << std::endl;
        // Read from file
        std::ifstream file(argv[1]);
        if (!file.is_open()) {
            std::cerr << "Error: Could not open file " << argv[1] << std::endl;
            return 1;
        }
        std::stringstream buffer;
        buffer << file.rdbuf();
        code = buffer.str();
        std::cout << "=== Testing from file: " << argv[1] << " ===\n";
    } else {
        std::cout << "DEBUG: No command line args, reading from stdin" << std::endl;
        // Read from stdin
        std::stringstream buffer;
        std::string line;
        
        // Check if stdin has data available without blocking
        std::cout << "DEBUG: Checking stdin availability" << std::endl;
        
        // Instead of trying to read from stdin, just use default test directly
        std::cout << "DEBUG: Skipping stdin read, using default test" << std::endl;
        code = ""; // This will trigger the default test below
        
        // If no stdin input, use default test
        if (code.empty()) {
            std::cout << "DEBUG: Using default test code" << std::endl;
            code = R"(
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
            std::cout << "=== Testing complex nested closures with multiple scope levels ===\n";
        }
    }

    
    Parser parser;
    Analyzer analyzer;
    Codegen codeGen;
    
    std::cout << "DEBUG: Starting parsing..." << std::endl;
    auto ast = parser.parse(code);
    std::cout << "DEBUG: Parsing completed successfully" << std::endl;
    
    std::cout << "DEBUG: Starting analysis..." << std::endl;
    analyzer.analyze(ast.get());
    std::cout << "DEBUG: Analysis completed successfully" << std::endl;
    // printAST(ast.get()); // Commented out - missing implementation
    
    // Debug: Check what address print_int64 actually has
    uint64_t actual_print_addr = reinterpret_cast<uint64_t>(print_int64);
    std::cout << "DEBUG: Actual print_int64 address: 0x" << std::hex << actual_print_addr << std::dec << std::endl;
    
    std::cout << "DEBUG: Starting code generation..." << std::endl;
    codeGen.generateProgram(*ast);
    std::cout << "DEBUG: Code generation completed successfully" << std::endl;
    
    std::cout << "DEBUG: Writing program to executable..." << std::endl;
    codeGen.writeProgramToExecutable();
    std::cout << "DEBUG: Program written successfully" << std::endl;
    
    return 0;
}
