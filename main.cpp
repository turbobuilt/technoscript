#include "parser.h"
#include "analyzer.h"
#include <iostream>
#include <fstream>
#include <sstream>

void printAST(ASTNode* node, int indent = 0) {
    std::string spaces(indent * 2, ' ');
    std::cout << spaces;
    
    switch (node->type) {
        case NodeType::PROGRAM: std::cout << "PROGRAM"; break;
        case NodeType::LEXICAL_SCOPE: {
            auto scope = static_cast<LexicalScopeNode*>(node);
            std::cout << "SCOPE(depth=" << scope->depth << ")";
            break;
        }
        case NodeType::VAR_DECL: 
            std::cout << "VAR " << static_cast<VarDeclNode*>(node)->varName; 
            break;
        case NodeType::FUNCTION_DECL: std::cout << "FUNC " << node->value; break;
        case NodeType::FUNCTION_CALL: std::cout << "CALL " << node->value; break;
        case NodeType::IDENTIFIER: {
            std::cout << "ID " << node->value;
            if (node->varRef) {
                std::cout << " -> depth" << node->varRef->scopeDepth;
            }
            break;
        }
        case NodeType::LITERAL: std::cout << "LIT " << node->value; break;
        case NodeType::PRINT_STMT: std::cout << "PRINT"; break;
        case NodeType::GO_STMT: std::cout << "GO"; break;
    }
    std::cout << "\n";
    
    for (auto& child : node->children) {
        printAST(child.get(), indent + 1);
    }
    
    if (node->type == NodeType::FUNCTION_DECL) {
        auto func = static_cast<FunctionDeclNode*>(node);
        if (func->scope) printAST(func->scope.get(), indent + 1);
    }
}

int main() {
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
var outer1: int64 = 41;
var outer: int64 = 42;
function level1() {
    var middle: int64 = 10;
    function level2() {
        var inner: int64 = 5;
        function level3() {
            print(outer, middle, inner)
        }
        level3()
    }
    level2()
}
level1()
    )";
    
    Parser parser;
    Analyzer analyzer;
    
    std::cout << "=== Parsing Code 1 ===\n";
    auto ast1 = parser.parse(code1);
    analyzer.analyze(ast1.get());
    printAST(ast1.get());
    
    std::cout << "\n=== Parsing Code 2 ===\n";
    auto ast2 = parser.parse(code2);
    analyzer.analyze(ast2.get());
    printAST(ast2.get());
    
    return 0;
}
