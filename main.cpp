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
var z: int64 = 22;
function test(x: int64) {
    print(x);
    print(z);
}
var a: int64 = 42;
test(a);a
)";
    std::cout << "=== Testing class method with 'this' ===\n";

    
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
    
    // Debug: Check what address print_int64 actually has
    uint64_t actual_print_addr = reinterpret_cast<uint64_t>(print_int64);
    std::cout << "DEBUG: Actual print_int64 address: 0x" << std::hex << actual_print_addr << std::dec << std::endl;
    
    std::cout << "DEBUG: Starting code generation..." << std::endl;
    codeGen.generateProgram(*ast, parser.getClassRegistry());
    std::cout << "DEBUG: Code generation completed successfully" << std::endl;
    
    // Start the garbage collector
    GarbageCollector::getInstance().start();
    std::cout << "DEBUG: Garbage collector started" << std::endl;
    
    // Spawn the main program as a goroutine instead of running it directly
    EventLoop::getInstance().spawnGoroutine([&codeGen]() {
        std::cout << "\n=== Main goroutine starting ===" << std::endl;
        codeGen.run();
        std::cout << "=== Main goroutine finished ===" << std::endl;
    });
    
    // Start the event loop to handle the main goroutine and any spawned goroutines
    runtime_start_event_loop();
    
    // Stop the garbage collector
    GarbageCollector::getInstance().stop();
    std::cout << "DEBUG: Garbage collector stopped" << std::endl;
    
    return 0;
}
