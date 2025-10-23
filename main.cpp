#include "parser.h"
#include "analyzer.h"
#include "ast_printer.h"
#include "goroutine.h"
#include "gc.h"
#include <iostream>
#include "codegen.h"

int main(int argc, char* argv[]) {
    std::cout << "DEBUG: Program started" << std::endl;
    std::cout.flush();
    
    std::cout << "DEBUG: Using built-in test program" << std::endl;
        std::string code = R"(
var x = 10;
print(x);
)";
// class Dog {
//     age: int64
//     printAge() {
//         print(this.age);
//     }
//     operator [](slice: TensorAccess): int64 {
//         print(slice[0].start);
//         print(slice[0].stop);
//         print(slice[0].step);
//     }
// }
// var d: Dog = new Dog();
// var x: int64 = 5;
// d[0:10:2];
// )";
    std::cout << "=== Testing safe unordered list ===\n";

    
    Parser parser;
    Analyzer analyzer;
    Codegen codeGen;
    
    std::cout << "DEBUG: Starting parsing..." << std::endl;
    auto ast = parser.parse(code);
    std::cout << "DEBUG: Parsing completed successfully" << std::endl;
    
    std::cout << "DEBUG: Starting analysis..." << std::endl;
    analyzer.analyze(ast.get(), parser.getClassRegistry());
    std::cout << "DEBUG: Analysis completed successfully" << std::endl;
    
    // Build class metadata registry (needed for GC tracing)
    std::cout << "DEBUG: Building class metadata registry..." << std::endl;
    MetadataRegistry::getInstance().buildClassMetadata(parser.getClassRegistry());
    std::cout << "DEBUG: Class metadata registry built successfully" << std::endl;
    
    std::cout << "DEBUG: Starting code generation..." << std::endl;
    codeGen.generateProgram(*ast, parser.getClassRegistry(), parser.getFunctionRegistry());
    std::cout << "DEBUG: Code generation completed successfully" << std::endl;
    
    // Directly run generated program for debugging
    std::cout << "\n=== Running program directly ===" << std::endl;
    codeGen.run();
    std::cout << "=== Program finished ===" << std::endl;
    
    return 0;
}
