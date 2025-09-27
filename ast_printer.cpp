#include "ast_printer.h"
#include <iostream>

void printAST(ASTNode* node, int indent) {
    std::string spaces(indent * 2, ' ');
    std::cout << spaces;
    
    switch (node->type) {
        case AstNodeType::FUNCTION_DECL: {
            auto scope = static_cast<LexicalScopeNode*>(node);
            std::cout << "SCOPE(depth=" << scope->depth << ")";
            
            // This scope is a function
            auto func = static_cast<FunctionDeclNode*>(scope);
            std::cout << " FUNC(" << func->funcName << ")";
            
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
            
            // Print scope parameter index map for codegen
            if (!scope->scopeDepthToParentParameterIndexMap.empty()) {
                std::cout << " [param-map:";
                for (auto& [depth, paramIndex] : scope->scopeDepthToParentParameterIndexMap) {
                    std::cout << " " << depth << "->" << paramIndex;
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
        case AstNodeType::VAR_DECL: 
            std::cout << "VAR " << static_cast<VarDeclNode*>(node)->varName; 
            break;
        case AstNodeType::FUNCTION_CALL: {
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
        case AstNodeType::IDENTIFIER: {
            std::cout << "ID " << node->value;
            if (node->varRef) {
                std::cout << " -> depth" << node->varRef->definedIn->depth;
            }
            break;
        }
        case AstNodeType::LITERAL: std::cout << "LIT " << node->value; break;
        case AstNodeType::PRINT_STMT: std::cout << "PRINT"; break;
        case AstNodeType::GO_STMT: std::cout << "GO"; break;
    }
    std::cout << "\n";
    
    for (auto& child : node->children) {
        printAST(child.get(), indent + 1);
    }
}
