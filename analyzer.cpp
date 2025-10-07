#include "analyzer.h"
#include <iostream>

void Analyzer::analyze(LexicalScopeNode* root, const std::map<std::string, ClassDeclNode*>& classes) {
    classRegistry = &classes;
    
    std::cout << "DEBUG Analyzer: Phase 1 - Analyzing classes (inheritance, layout, vtables)..." << std::endl;
    
    // Phase 1: Process all classes FIRST - single pass through classes
    // This must happen before analyzing the AST because object layouts need to be known
    for (const auto& [className, classDecl] : classes) {
        std::cout << "DEBUG: Processing class '" << className << "'" << std::endl;
        
        // Step 1: Resolve parent class references
        resolveClassInheritance(classDecl);
        
        // Step 2: Calculate object layout with inheritance
        calculateClassLayout(classDecl);
        
        // Step 3: Build vtable
        buildClassVTable(classDecl);
        
        // Step 4: Re-pack to calculate method closure sizes now that vtable is built
        classDecl->pack();
    }
    
    std::cout << "DEBUG Analyzer: Phase 2 - Single-pass AST analysis..." << std::endl;
    analyzeNodeSinglePass(root, nullptr, 0);
    
    std::cout << "DEBUG Analyzer: Analysis completed" << std::endl;
}

// Single-pass analysis that does everything in the correct order
void Analyzer::analyzeNodeSinglePass(ASTNode* node, LexicalScopeNode* parentScope, int depth) {
    // Prevent infinite recursion
    if (depth > RobustnessLimits::MAX_AST_RECURSION_DEPTH) {
        throw std::runtime_error("AST recursion depth exceeded " + 
                               std::to_string(RobustnessLimits::MAX_AST_RECURSION_DEPTH) + " in single-pass analysis");
    }
    
    LexicalScopeNode* currentScope = parentScope;
    
    // Step 1: Setup parent pointers and depth for scope nodes (on the way down)
    if (node->type == AstNodeType::FUNCTION_DECL || node->type == AstNodeType::FOR_STMT || node->type == AstNodeType::BLOCK_STMT) {
        auto scope = static_cast<LexicalScopeNode*>(node);
        scope->parentFunctionScope = parentScope;
        scope->depth = depth;
        currentScope = scope;
        std::string typeStr = (node->type == AstNodeType::FUNCTION_DECL) ? "FUNCTION" : 
                             (node->type == AstNodeType::FOR_STMT) ? "FOR" : "BLOCK";
        std::cout << "DEBUG: Setup scope at depth " << depth << " (type: " << typeStr << ")" << std::endl;
    }
    
    // Step 1.5: Resolve class references for VarDecl nodes with custom types
    if (node->type == AstNodeType::VAR_DECL) {
        auto varDecl = static_cast<VarDeclNode*>(node);
        if (varDecl->varType == DataType::OBJECT && !varDecl->customTypeName.empty()) {
            // Find the variable in the current scope and set its classNode
            if (currentScope) {
                auto varIt = currentScope->variables.find(varDecl->varName);
                if (varIt != currentScope->variables.end()) {
                    varIt->second.classNode = findClass(varDecl->customTypeName);
                    std::cout << "DEBUG: Resolved class '" << varDecl->customTypeName 
                              << "' for variable '" << varDecl->varName << "'" << std::endl;
                }
            }
        }
    }
    
    // Step 2: Analyze current node for variable references
    if (node->type == AstNodeType::IDENTIFIER || node->type == AstNodeType::FUNCTION_CALL) {
        node->varRef = findVariable(node->value, currentScope);
        
        // Set the accessedIn property for identifier nodes
        if (node->type == AstNodeType::IDENTIFIER) {
            auto identifier = static_cast<IdentifierNode*>(node);
            identifier->accessedIn = currentScope;
        } else if (node->type == AstNodeType::FUNCTION_CALL) {
            auto funcCall = static_cast<FunctionCallNode*>(node);
            funcCall->accessedIn = currentScope;
            
            // Analyze function call arguments
            for (auto& arg : funcCall->args) {
                analyzeNodeSinglePass(arg.get(), currentScope, depth + 1);
            }
        }
    } else if (node->type == AstNodeType::SETTIMEOUT_STMT) {
        // Analyze setTimeout statement - need to resolve function name and delay
        auto setTimeoutStmt = static_cast<SetTimeoutStmtNode*>(node);
        
        // Analyze the function name identifier
        if (setTimeoutStmt->functionName) {
            analyzeNodeSinglePass(setTimeoutStmt->functionName.get(), currentScope, depth + 1);
        }
        
        // Analyze the delay literal
        if (setTimeoutStmt->delay) {
            analyzeNodeSinglePass(setTimeoutStmt->delay.get(), currentScope, depth + 1);
        }
    } else if (node->type == AstNodeType::GO_STMT) {
        // Analyze go statement - need to resolve the function call
        auto goStmt = static_cast<GoStmtNode*>(node);
        
        // Analyze the function call (this will resolve varRef)
        if (goStmt->functionCall) {
            analyzeNodeSinglePass(goStmt->functionCall.get(), currentScope, depth + 1);
        }
    } else if (node->type == AstNodeType::FOR_STMT) {
        // Special handling for for loop - need to analyze init, condition, update in the for loop's scope
        auto forStmt = static_cast<ForStmtNode*>(node);
        
        // Analyze initialization (e.g., let i: int64 = 0) in the for loop's own scope
        if (forStmt->init) {
            analyzeNodeSinglePass(forStmt->init.get(), currentScope, depth + 1);
        }
        
        // Analyze condition (e.g., i < 2) in the for loop's scope
        if (forStmt->condition) {
            analyzeNodeSinglePass(forStmt->condition.get(), currentScope, depth + 1);
        }
        
        // Analyze update (e.g., ++i) in the for loop's scope  
        if (forStmt->update) {
            analyzeNodeSinglePass(forStmt->update.get(), currentScope, depth + 1);
        }
    } else if (node->type == AstNodeType::BINARY_EXPR) {
        // Handle binary expressions - analyze left and right operands
        auto binaryExpr = static_cast<BinaryExprNode*>(node);
        if (binaryExpr->left) {
            analyzeNodeSinglePass(binaryExpr->left.get(), currentScope, depth + 1);
        }
        if (binaryExpr->right) {
            analyzeNodeSinglePass(binaryExpr->right.get(), currentScope, depth + 1);
        }
    } else if (node->type == AstNodeType::UNARY_EXPR) {
        // Handle unary expressions - analyze the operand
        auto unaryExpr = static_cast<UnaryExprNode*>(node);
        if (unaryExpr->operand) {
            analyzeNodeSinglePass(unaryExpr->operand.get(), currentScope, depth + 1);
        }
    } else if (node->type == AstNodeType::NEW_EXPR) {
        // Handle new expressions - resolve the class reference
        auto newExpr = static_cast<NewExprNode*>(node);
        newExpr->classRef = findClass(newExpr->className);
        std::cout << "DEBUG: Resolved NEW_EXPR for class '" << newExpr->className << "'" << std::endl;
    } else if (node->type == AstNodeType::MEMBER_ACCESS) {
        // Handle member access - resolve class and field offset
        auto memberAccess = static_cast<MemberAccessNode*>(node);
        
        // First analyze the object expression
        analyzeNodeSinglePass(memberAccess->object.get(), currentScope, depth + 1);
        
        // Get the object's type to find the class
        ASTNode* objectNode = memberAccess->object.get();
        ClassDeclNode* objectClass = nullptr;
        
        if (objectNode->type == AstNodeType::IDENTIFIER) {
            auto identifier = static_cast<IdentifierNode*>(objectNode);
            if (identifier->varRef && identifier->varRef->type == DataType::OBJECT) {
                objectClass = identifier->varRef->classNode;
            }
        } else if (objectNode->type == AstNodeType::THIS_EXPR) {
            // Handle 'this.field' access in methods
            auto thisNode = static_cast<ThisNode*>(objectNode);
            objectClass = thisNode->classContext;
        }
        
        if (!objectClass) {
            throw std::runtime_error("Cannot resolve class for member access on: " + memberAccess->memberName);
        }
        
        // Find the field in the class (including inherited fields)
        auto fieldIt = objectClass->fields.find(memberAccess->memberName);
        if (fieldIt == objectClass->fields.end()) {
            // Check parent classes for the field
            bool foundInParent = false;
            for (ClassDeclNode* parent : objectClass->parentRefs) {
                auto parentFieldIt = parent->fields.find(memberAccess->memberName);
                if (parentFieldIt != parent->fields.end()) {
                    // Found in parent - use parent's class and calculate offset
                    memberAccess->classRef = parent;
                    int parentOffset = objectClass->parentOffsets[parent->className];
                    memberAccess->memberOffset = parentOffset + parentFieldIt->second.offset;
                    foundInParent = true;
                    std::cout << "DEBUG: Resolved MEMBER_ACCESS for field '" << memberAccess->memberName 
                              << "' from parent '" << parent->className 
                              << "' at offset " << memberAccess->memberOffset 
                              << " in class '" << objectClass->className << "'" << std::endl;
                    break;
                }
            }
            
            if (!foundInParent) {
                throw std::runtime_error("Field '" + memberAccess->memberName + "' not found in class '" + objectClass->className + "' or its parents");
            }
        } else {
            // Found in own class
            memberAccess->classRef = objectClass;
            memberAccess->memberOffset = fieldIt->second.offset;
            
            std::cout << "DEBUG: Resolved MEMBER_ACCESS for field '" << memberAccess->memberName 
                      << "' at offset " << memberAccess->memberOffset 
                      << " in class '" << objectClass->className << "'" << std::endl;
        }
    } else if (node->type == AstNodeType::MEMBER_ASSIGN) {
        // Handle member assignment
        auto memberAssign = static_cast<MemberAssignNode*>(node);
        
        // Analyze the member access part
        if (memberAssign->member) {
            analyzeNodeSinglePass(memberAssign->member.get(), currentScope, depth + 1);
        }
        
        // Analyze the value expression
        if (memberAssign->value) {
            analyzeNodeSinglePass(memberAssign->value.get(), currentScope, depth + 1);
        }
    } else if (node->type == AstNodeType::CLASS_DECL) {
        // Class declarations are already processed in Phase 1, but we need to analyze methods here
        auto classDecl = static_cast<ClassDeclNode*>(node);
        std::cout << "DEBUG: Analyzing methods for class '" << classDecl->className << "'" << std::endl;
        
        // Save previous context
        ClassDeclNode* prevClassContext = currentClassContext;
        currentClassContext = classDecl;
        
        // Analyze each method as a closure with 'this' context
        for (auto& [methodName, method] : classDecl->methods) {
            std::cout << "DEBUG: Analyzing method '" << methodName << "' in class '" << classDecl->className << "'" << std::endl;
            
            // Save previous method context
            FunctionDeclNode* prevMethodContext = currentMethodContext;
            currentMethodContext = method.get();
            
            // Add implicit 'this' parameter to method's scope
            // 'this' is always the first parameter, pointing to the object instance
            VariableInfo thisParam;
            thisParam.type = DataType::OBJECT;
            thisParam.name = "this";
            thisParam.classNode = classDecl;
            thisParam.size = 8; // pointer size
            thisParam.definedIn = method.get();
            
            // Add 'this' to variables map (for variable lookup)
            method->variables["this"] = thisParam;
            
            // Add 'this' to params vector (for parameter tracking)
            method->params.insert(method->params.begin(), "this");
            
            // CRITICAL: Add 'this' to paramsInfo (for codegen parameter layout)
            // This must be the FIRST parameter, so insert at the beginning
            method->paramsInfo.insert(method->paramsInfo.begin(), thisParam);
            
            std::cout << "DEBUG: Added 'this' parameter to method '" << methodName 
                      << "', total params: " << method->paramsInfo.size() << std::endl;
            
            // Now analyze the method body with this context
            analyzeNodeSinglePass(method.get(), currentScope, depth + 1);
            
            // Restore method context
            currentMethodContext = prevMethodContext;
        }
        
        // Restore class context
        currentClassContext = prevClassContext;
        
    } else if (node->type == AstNodeType::METHOD_CALL) {
        // Handle method calls - resolve method and calculate this offset
        auto methodCall = static_cast<MethodCallNode*>(node);
        
        // First analyze the object expression
        analyzeNodeSinglePass(methodCall->object.get(), currentScope, depth + 1);
        
        // Get the object's class
        ASTNode* objectNode = methodCall->object.get();
        ClassDeclNode* objectClass = nullptr;
        
        if (objectNode->type == AstNodeType::IDENTIFIER) {
            auto identifier = static_cast<IdentifierNode*>(objectNode);
            if (identifier->varRef && identifier->varRef->type == DataType::OBJECT) {
                objectClass = identifier->varRef->classNode;
            }
        } else if (objectNode->type == AstNodeType::THIS_EXPR) {
            // 'this' in a method call
            objectClass = currentClassContext;
        }
        
        if (!objectClass) {
            throw std::runtime_error("Cannot resolve class for method call: " + methodCall->methodName);
        }
        
        // Find the method in the class hierarchy (vtable)
        auto* vtableEntry = findMethodInClass(objectClass, methodCall->methodName);
        if (!vtableEntry) {
            throw std::runtime_error("Method '" + methodCall->methodName + "' not found in class '" + objectClass->className + "'");
        }
        
        methodCall->resolvedMethod = vtableEntry->method;
        methodCall->thisOffset = vtableEntry->thisOffset;
        methodCall->objectClass = objectClass;
        
        // Find vtable index
        for (size_t i = 0; i < objectClass->vtable.size(); i++) {
            if (objectClass->vtable[i].methodName == methodCall->methodName) {
                methodCall->vtableIndex = i;
                methodCall->methodClosureOffset = objectClass->vtable[i].closureOffsetInObject;
                break;
            }
        }
        
        std::cout << "DEBUG: Resolved METHOD_CALL '" << methodCall->methodName 
                  << "' in class '" << objectClass->className 
                  << "' at vtable index " << methodCall->vtableIndex
                  << " with this offset " << methodCall->thisOffset
                  << " and closure offset " << methodCall->methodClosureOffset << std::endl;
        
        // Analyze method call arguments
        for (auto& arg : methodCall->args) {
            analyzeNodeSinglePass(arg.get(), currentScope, depth + 1);
        }
        
    } else if (node->type == AstNodeType::THIS_EXPR) {
        // Handle 'this' keyword
        auto thisNode = static_cast<ThisNode*>(node);
        
        if (!currentMethodContext) {
            throw std::runtime_error("'this' used outside of method context");
        }
        
        thisNode->methodContext = currentMethodContext;
        thisNode->classContext = currentClassContext;
        
        // 'this' references the implicit 'this' parameter
        thisNode->varRef = findVariable("this", currentScope);
        
        std::cout << "DEBUG: Resolved THIS_EXPR in method of class '" 
                  << (currentClassContext ? currentClassContext->className : "unknown") << "'" << std::endl;
    }
    
    // Step 3: Recursively process all children
    for (auto& child : node->children) {
        analyzeNodeSinglePass(child.get(), currentScope, depth + 1);
    }
    
    // Step 4: Post-process scope nodes (on the way back up)
    if (node->type == AstNodeType::FUNCTION_DECL || node->type == AstNodeType::FOR_STMT || node->type == AstNodeType::BLOCK_STMT) {
        auto scope = static_cast<LexicalScopeNode*>(node);
        
        // Update allNeeded arrays now that all children have been processed
        scope->updateAllNeeded();
        std::cout << "DEBUG: Scope depth " << scope->depth << " has " << scope->allNeeded.size() << " needed scopes" << std::endl;
        
        // For function scopes, update closure sizes now that allNeeded is calculated
        if (node->type == AstNodeType::FUNCTION_DECL) {
            for (auto& [name, varInfo] : scope->variables) {
                if (varInfo.type == DataType::CLOSURE && varInfo.funcNode) {
                    size_t old_size = varInfo.size;
                    // New closure layout: [function_address] [size] [scope_pointer_1] ... [scope_pointer_N]
                    varInfo.size = 8 + 8 + (varInfo.funcNode->allNeeded.size() * 8); // function + size + scopes
                    std::cout << "DEBUG: Updated closure '" << name << "' size from " << old_size 
                             << " to " << varInfo.size << " (needs " << varInfo.funcNode->allNeeded.size() << " scopes)" << std::endl;
                }
            }
        }
        
        // Pack the scope
        scope->pack();
        
        // Build parameter index maps if it's a function scope or block scope
        if (node->type == AstNodeType::FUNCTION_DECL || node->type == AstNodeType::BLOCK_STMT) {
            scope->buildScopeDepthToParentParameterIndexMap();
        }

        
        std::cout << "DEBUG: Completed post-processing for scope at depth " << scope->depth << std::endl;
    }
}

VariableInfo* Analyzer::findVariable(const std::string& name, LexicalScopeNode* scope) {
    std::cout << "DEBUG findVariable: Looking for '" << name << "' in scope at depth " << (scope ? scope->depth : -1) << std::endl;
    
    LexicalScopeNode* current = scope;
    LexicalScopeNode* defScope = nullptr;
    
    // Simple lexical scope traversal - check current scope, then parents
    while (current) {
        std::cout << "DEBUG findVariable: Checking scope at depth " << current->depth << " with " << current->variables.size() << " variables" << std::endl;
        for (const auto& [varName, varInfo] : current->variables) {
            std::cout << "DEBUG findVariable:   - Found variable '" << varName << "'" << std::endl;
        }
        
        auto it = current->variables.find(name);
        if (it != current->variables.end()) {
            std::cout << "DEBUG findVariable: Found '" << name << "' in scope at depth " << current->depth << std::endl;
            defScope = current;
            break;
        }
        current = current->parentFunctionScope;
    }
    
    if (!defScope) {
        std::cout << "DEBUG findVariable: Variable '" << name << "' NOT FOUND" << std::endl;
        throw std::runtime_error("Variable '" + name + "' not found in scope");
    }
    
    // Add dependency tracking for closures
    if (defScope != scope) {
        addParentDep(scope, defScope->depth);
        
        // Add descendant dependencies to intermediate scopes
        LexicalScopeNode* parent = scope->parentFunctionScope;
        while (parent && parent != defScope) {
            addDescendantDep(parent, defScope->depth);
            parent = parent->parentFunctionScope;
        }
    }
    
    return &defScope->variables[name];
}

ClassDeclNode* Analyzer::findClass(const std::string& className) {
    if (!classRegistry) {
        throw std::runtime_error("Class registry not initialized");
    }
    
    auto it = classRegistry->find(className);
    if (it == classRegistry->end()) {
        throw std::runtime_error("Class '" + className + "' not found");
    }
    
    return it->second;
}

// Helper methods for dependency tracking
void Analyzer::addParentDep(LexicalScopeNode* scope, int depthIdx) {
    scope->parentDeps.insert(depthIdx);
}

void Analyzer::addDescendantDep(LexicalScopeNode* scope, int depthIdx) {
    scope->descendantDeps.insert(depthIdx);
}

// Resolve parent class references for a class
void Analyzer::resolveClassInheritance(ClassDeclNode* classDecl) {
    classDecl->parentRefs.clear();
    
    for (const std::string& parentName : classDecl->parentClassNames) {
        ClassDeclNode* parentClass = findClass(parentName);
        classDecl->parentRefs.push_back(parentClass);
        std::cout << "DEBUG: Resolved parent class '" << parentName << "' for class '" << classDecl->className << "'" << std::endl;
    }
}

// Calculate object layout with multiple inheritance
void Analyzer::calculateClassLayout(ClassDeclNode* classDecl) {
    std::cout << "DEBUG: Calculating layout for class '" << classDecl->className << "'" << std::endl;
    
    int currentOffset = 0; // Fields start at offset 0 (header is separate)
    classDecl->allFieldsInOrder.clear();
    classDecl->parentOffsets.clear();
    
    // Layout parent class fields in order
    for (ClassDeclNode* parent : classDecl->parentRefs) {
        classDecl->parentOffsets[parent->className] = currentOffset;
        std::cout << "DEBUG:   Parent '" << parent->className << "' at offset " << currentOffset << std::endl;
        
        // Add parent's fields to layout (recursively includes their parents)
        // For now, we'll add parent's own fields (inheritance is linear for simplicity)
        for (const auto& [fieldName, fieldInfo] : parent->fields) {
            classDecl->allFieldsInOrder.push_back(parent->className + "::" + fieldName);
            std::cout << "DEBUG:     Field '" << fieldName << "' from parent at offset " 
                      << (currentOffset + fieldInfo.offset) << std::endl;
        }
        
        currentOffset += parent->totalSize;
    }
    
    // Layout own fields
    for (auto& [fieldName, fieldInfo] : classDecl->fields) {
        // Adjust field offset to account for vtable pointer and parent fields
        fieldInfo.offset = currentOffset + fieldInfo.offset;
        classDecl->allFieldsInOrder.push_back(fieldName);
        std::cout << "DEBUG:   Own field '" << fieldName << "' at offset " << fieldInfo.offset << std::endl;
    }
    
    // Calculate total size: vtable ptr + all parent fields + own fields
    int ownFieldsSize = classDecl->totalSize; // This was calculated during pack() in parser
    classDecl->totalSize = currentOffset + ownFieldsSize;
    
    std::cout << "DEBUG: Class '" << classDecl->className << "' total size: " << classDecl->totalSize 
              << " (vtable: 8, parents: " << (currentOffset - 8) << ", own: " << ownFieldsSize << ")" << std::endl;
}

// Build vtable for a class with multiple inheritance
void Analyzer::buildClassVTable(ClassDeclNode* classDecl) {
    std::cout << "DEBUG: Building vtable for class '" << classDecl->className << "'" << std::endl;
    
    classDecl->vtable.clear();
    std::map<std::string, int> methodToIndex; // Track which methods we've added
    
    // Step 1: Add parent class methods with appropriate 'this' offset adjustments
    for (size_t i = 0; i < classDecl->parentRefs.size(); i++) {
        ClassDeclNode* parent = classDecl->parentRefs[i];
        int parentOffset = classDecl->parentOffsets[parent->className];
        
        // Add parent's methods (or their overridden versions if parent has vtable)
        for (auto& [methodName, method] : parent->methods) {
            if (methodToIndex.find(methodName) == methodToIndex.end()) {
                // Method not yet in vtable, add it
                ClassDeclNode::VTableEntry entry;
                entry.methodName = methodName;
                entry.method = method.get();
                entry.thisOffset = parentOffset; // Adjust 'this' to point to parent's data
                entry.definingClass = parent;
                
                methodToIndex[methodName] = classDecl->vtable.size();
                classDecl->vtable.push_back(entry);
                
                std::cout << "DEBUG:   Added parent method '" << methodName 
                          << "' from '" << parent->className 
                          << "' at index " << (classDecl->vtable.size() - 1)
                          << " with this offset " << parentOffset << std::endl;
            }
        }
    }
    
    // Step 2: Add or override with own methods (this offset = 0 since own fields come after parents)
    int ownThisOffset = 0; // Fields start at offset 0 (header is separate)
    for (const auto& parent : classDecl->parentRefs) {
        ownThisOffset += parent->totalSize;
    }
    
    for (auto& [methodName, method] : classDecl->methods) {
        auto it = methodToIndex.find(methodName);
        if (it != methodToIndex.end()) {
            // Override parent method
            int index = it->second;
            classDecl->vtable[index].method = method.get();
            classDecl->vtable[index].thisOffset = 0; // Own methods use base object pointer
            classDecl->vtable[index].definingClass = classDecl;
            
            std::cout << "DEBUG:   Overriding method '" << methodName 
                      << "' at index " << index 
                      << " with this offset 0" << std::endl;
        } else {
            // New method
            ClassDeclNode::VTableEntry entry;
            entry.methodName = methodName;
            entry.method = method.get();
            entry.thisOffset = 0; // Own methods use base object pointer
            entry.definingClass = classDecl;
            
            methodToIndex[methodName] = classDecl->vtable.size();
            classDecl->vtable.push_back(entry);
            
            std::cout << "DEBUG:   Added own method '" << methodName 
                      << "' at index " << (classDecl->vtable.size() - 1)
                      << " with this offset 0" << std::endl;
        }
    }
    
    std::cout << "DEBUG: Class '" << classDecl->className << "' vtable size: " << classDecl->vtable.size() << std::endl;
}

// Find a method in a class's vtable
ClassDeclNode::VTableEntry* Analyzer::findMethodInClass(ClassDeclNode* classDecl, const std::string& methodName) {
    for (auto& entry : classDecl->vtable) {
        if (entry.methodName == methodName) {
            return &entry;
        }
    }
    return nullptr;
}
