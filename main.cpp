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
        case NodeType::FUNCTION_DECL:
            // Fall through to LEXICAL_SCOPE
        case NodeType::LEXICAL_SCOPE: {
            auto scope = static_cast<LexicalScopeNode*>(node);
            std::cout << "SCOPE(depth=" << scope->depth << ")";
            
            // If this scope is also a function
            if (node->type == NodeType::FUNCTION_DECL) {
                auto func = static_cast<FunctionDeclNode*>(scope);
                std::cout << " FUNC(" << func->funcName << ")";
            }
            
            // Print parent dependencies
            if (!scope->parentDeps.empty()) {
                std::cout << " [parent-deps:";
                for (int dep : scope->parentDeps) {
                    std::cout << " " << dep;
                }
                std::cout << "]";
            }
            
            // Print descendant dependencies
            if (!scope->descendantDeps.empty()) {
                std::cout << " [desc-deps:";
                for (int dep : scope->descendantDeps) {
                    std::cout << " " << dep;
                }
                std::cout << "]";
            }
            
            // Print all needed scopes
            if (!scope->allNeeded.empty()) {
                std::cout << " [all-needed:";
                for (int dep : scope->allNeeded) {
                    std::cout << " " << dep;
                }
                std::cout << "]";
            }
            
            // Print scope index map for codegen
            if (!scope->scopeIndexMap.empty()) {
                std::cout << " [scope-map:";
                for (auto& [depth, index] : scope->scopeIndexMap) {
                    std::cout << " " << depth << "->" << index;
                }
                std::cout << "]";
            }
            
            // Print packing info
            if (!scope->variables.empty()) {
                std::cout << " [size=" << scope->totalSize << "]";
                std::cout << " [vars:";
                for (auto& [name, var] : scope->variables) {
                    std::cout << " " << name << "@" << var.offset << "(";
                    if (var.type == DataType::INT32) {
                        std::cout << "i32";
                    } else if (var.type == DataType::INT64) {
                        std::cout << "i64";
                    } else if (var.type == DataType::CLOSURE) {
                        int closureSize = 8; // base size
                        if (var.funcNode) {
                            closureSize += var.funcNode->allNeeded.size() * 8;
                        }
                        std::cout << "closure:" << closureSize;
                    }
                    std::cout << ")";
                }
                std::cout << "]";
            }
            break;
        }
        case NodeType::VAR_DECL: 
            std::cout << "VAR " << static_cast<VarDeclNode*>(node)->varName; 
            break;
        case NodeType::FUNCTION_CALL: {
            auto* call = static_cast<FunctionCallNode*>(node);
            std::cout << "CALL " << call->value;
            if (!call->args.empty()) {
                std::cout << "(";
                for (size_t i = 0; i < call->args.size(); i++) {
                    if (i > 0) std::cout << ",";
                    printAST(call->args[i].get(), indent + 1);
                }
                std::cout << ")";
            }
            break;
        }
        case NodeType::IDENTIFIER: {
            std::cout << "ID " << node->value;
            if (node->varRef) {
                std::cout << " -> depth" << node->varRef->definedIn->depth;
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
        function level3() {
            print(big2, mini, medium)
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
