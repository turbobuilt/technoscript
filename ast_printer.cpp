#include "ast_printer.h"
#include <iostream>

void printAST(ASTNode* node, int indent) {
    std::string spaces(indent * 2, ' ');
    std::cout << spaces;
    
    switch (node->type) {
        case AstNodeType::AWAIT_EXPR:
            std::cout << "AWAIT_EXPR";
            break;
        case AstNodeType::SLEEP_CALL:
            std::cout << "SLEEP_CALL";
            break;
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
                        int closureSize = 16; // function_address (8) + size (8)
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
        case AstNodeType::SETTIMEOUT_STMT: std::cout << "SETTIMEOUT"; break;
        case AstNodeType::FOR_STMT: std::cout << "FOR_STMT"; break;
        case AstNodeType::LET_DECL: {
            auto* let = static_cast<LetDeclNode*>(node);
            std::cout << "LET " << let->varName;
            break;
        }
        case AstNodeType::BINARY_EXPR: {
            auto* binary = static_cast<BinaryExprNode*>(node);
            std::cout << "BINARY_EXPR (" << binary->operator_type << ")";
            break;
        }
        case AstNodeType::UNARY_EXPR: {
            auto* unary = static_cast<UnaryExprNode*>(node);
            std::cout << "UNARY_EXPR (" << unary->operator_type << ")";
            break;
        }
        case AstNodeType::BLOCK_STMT: {
            auto* scope = static_cast<LexicalScopeNode*>(node);
            std::cout << "BLOCK_STMT(depth=" << scope->depth << ")";
            break;
        }
        case AstNodeType::CLASS_DECL: {
            auto* classDecl = static_cast<ClassDeclNode*>(node);
            std::cout << "CLASS " << classDecl->className;
            if (!classDecl->parentClassNames.empty()) {
                std::cout << " : ";
                for (size_t i = 0; i < classDecl->parentClassNames.empty(); i++) {
                    if (i > 0) std::cout << ", ";
                    std::cout << classDecl->parentClassNames[i];
                }
            }
            std::cout << " (size=" << classDecl->totalSize << ") {";
            for (const auto& [fieldName, fieldInfo] : classDecl->fields) {
                std::cout << " " << fieldName << ":";
                if (fieldInfo.type == DataType::INT32) std::cout << "int32";
                else if (fieldInfo.type == DataType::INT64) std::cout << "int64";
                else if (fieldInfo.type == DataType::OBJECT) std::cout << "object";
                std::cout << "@" << fieldInfo.offset;
            }
            if (!classDecl->methods.empty()) {
                std::cout << " methods:";
                for (const auto& [methodName, method] : classDecl->methods) {
                    std::cout << " " << methodName << "()";
                }
            }
            std::cout << " }";
            break;
        }
        case AstNodeType::NEW_EXPR: {
            auto* newExpr = static_cast<NewExprNode*>(node);
            std::cout << "NEW " << newExpr->className;
            break;
        }
        case AstNodeType::MEMBER_ACCESS: {
            auto* memberAccess = static_cast<MemberAccessNode*>(node);
            std::cout << "MEMBER_ACCESS ." << memberAccess->memberName;
            break;
        }
        case AstNodeType::MEMBER_ASSIGN: {
            std::cout << "MEMBER_ASSIGN";
            break;
        }
        case AstNodeType::METHOD_CALL: {
            auto* methodCall = static_cast<MethodCallNode*>(node);
            std::cout << "METHOD_CALL ." << methodCall->methodName << "(";
            for (size_t i = 0; i < methodCall->args.size(); i++) {
                if (i > 0) std::cout << ", ";
                std::cout << "arg" << i;
            }
            std::cout << ")";
            break;
        }
        case AstNodeType::THIS_EXPR: {
            std::cout << "THIS";
            break;
        }
    }
    std::cout << "\n";
    
    for (auto& child : node->children) {
        printAST(child.get(), indent + 1);
    }
}
