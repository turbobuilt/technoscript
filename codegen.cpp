#include "codegen.h"
#include <iostream>
#include <cstring>

void Codegen::initExternFunctions() {
    // Get addresses of extern C functions for maximum performance
    extern_function_addresses["print_int64"] = reinterpret_cast<uint64_t>(print_int64);
}

size_t Codegen::allocateScope(LexicalScopeNode* scope, bool is_global) {
    size_t total_length = 0;
    
    // Save R15 (current lexical scope pointer) on stack
    total_length += emitter.emitPushR15();
    
    // Allocate memory for this scope using mmap syscall
    // mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
    total_length += emitter.emitMovRAXImm64(9);        // sys_mmap
    total_length += emitter.emitXorRdiRdi();           // addr = NULL (let kernel choose)
    total_length += emitter.emitMovRSIImm64(scope->totalSize); // length = scope size
    total_length += emitter.emitMovRDXImm64(3);        // prot = PROT_READ | PROT_WRITE
    total_length += emitter.emitMovRCXImm64(0x22);     // flags = MAP_PRIVATE | MAP_ANONYMOUS
    total_length += emitter.emitMovR8Imm64(-1);        // fd = -1
    total_length += emitter.emitMovR9Imm64(0);         // offset = 0
    total_length += emitter.emitSyscall();
    
    // Move allocated memory address to R15 (our lexical scope pointer)
    total_length += emitter.emitMovR15RAX();
    
    return total_length;
}

size_t Codegen::generateNode(ASTNode* node, LexicalScopeNode* current_scope) {
    size_t total_length = 0;
    
    switch (node->type) {
        case NodeType::VAR_DECL: {
            VarDeclNode* varDecl = static_cast<VarDeclNode*>(node);
            total_length += generateVarDecl(varDecl, current_scope);
            break;
        }
        case NodeType::LITERAL: {
            LiteralNode* literal = static_cast<LiteralNode*>(node);
            total_length += generateLiteral(literal);
            break;
        }
        case NodeType::IDENTIFIER: {
            IdentifierNode* identifier = static_cast<IdentifierNode*>(node);
            total_length += generateIdentifier(identifier, current_scope);
            break;
        }
        case NodeType::PRINT_STMT: {
            total_length += generatePrintStatement(node, current_scope);
            break;
        }
        case NodeType::FUNCTION_CALL:
        case NodeType::GO_STMT:
            // TODO: Implement these later
            break;
        default:
            // For other node types, just process children
            for (auto& child : node->children) {
                total_length += generateNode(child.get(), current_scope);
            }
            break;
    }
    
    return total_length;
}

size_t Codegen::generateVarDecl(VarDeclNode* varDecl, LexicalScopeNode* current_scope) {
    size_t total_length = 0;
    
    // Find the variable info in the current scope
    auto it = current_scope->variables.find(varDecl->varName);
    if (it == current_scope->variables.end()) {
        std::cerr << "Variable not found in scope: " << varDecl->varName << std::endl;
        return 0;
    }
    
    VariableInfo& varInfo = it->second;
    
    // Generate code for the initializer (if any)
    if (!varDecl->children.empty()) {
        // Assuming first child is the initializer
        total_length += generateNode(varDecl->children[0].get(), current_scope);
        
        // Store the value (currently in RAX) to R15 + offset
        if (varInfo.type == DataType::INT32) {
            total_length += emitter.emitMovDwordPtrR15PlusOffsetEAX(varInfo.offset);
        } else if (varInfo.type == DataType::INT64) {
            total_length += emitter.emitMovQwordPtrR15PlusOffsetRAX(varInfo.offset);
        }
    }
    
    return total_length;
}

size_t Codegen::generateLiteral(LiteralNode* literal) {
    // Convert literal value to integer and load into RAX
    int64_t value = std::stoll(literal->value);
    return emitter.emitMovRAXImm64(static_cast<uint64_t>(value));
}

size_t Codegen::generateIdentifier(IdentifierNode* identifier, LexicalScopeNode* current_scope) {
    // Get variable access info
    auto access = identifier->getVariableAccess(current_scope);
    
    // For now, assume it's in current scope (parameterIndex == -1)
    if (access.parameterIndex == -1) {
        // Load from R15 + offset into RAX
        if (identifier->varRef && identifier->varRef->type == DataType::INT32) {
            // mov eax, [r15+offset] - need to add this instruction
            // For now, load as 64-bit
            if (access.offset == 0) {
                return emitter.emitBytes({0x49, 0x8B, 0x07}); // mov rax, [r15]
            } else if (access.offset >= -128 && access.offset <= 127) {
                return emitter.emitBytes({0x49, 0x8B, 0x47, static_cast<uint8_t>(access.offset)}); // mov rax, [r15+offset8]
            } else {
                return emitter.emitBytes({0x49, 0x8B, 0x87}) + emitter.emitU32(static_cast<uint32_t>(access.offset)); // mov rax, [r15+offset32]
            }
        } else {
            // Load 64-bit value
            if (access.offset == 0) {
                return emitter.emitBytes({0x49, 0x8B, 0x07}); // mov rax, [r15]
            } else if (access.offset >= -128 && access.offset <= 127) {
                return emitter.emitBytes({0x49, 0x8B, 0x47, static_cast<uint8_t>(access.offset)}); // mov rax, [r15+offset8]
            } else {
                return emitter.emitBytes({0x49, 0x8B, 0x87}) + emitter.emitU32(static_cast<uint32_t>(access.offset)); // mov rax, [r15+offset32]
            }
        }
    }
    
    // TODO: Handle parent scope access
    return 0;
}

size_t Codegen::generatePrintStatement(ASTNode* node, LexicalScopeNode* current_scope) {
    size_t total_length = 0;
    
    // For each argument to print, generate code to load it into RDI and call print_int64
    for (auto& child : node->children) {
        // Generate code to load the value into RAX
        total_length += generateNode(child.get(), current_scope);
        
        // Move RAX to RDI (first argument register)
        total_length += emitter.emitBytes({0x48, 0x89, 0xC7}); // mov rdi, rax
        
        // Call print_int64 function
        uint64_t print_addr = extern_function_addresses["print_int64"];
        total_length += emitter.emitCallAbsolute(print_addr);
    }
    
    return total_length;
}

void Codegen::generateProgram(ASTNode& root) {
    emitter.clear();
    initExternFunctions();
    
    // Cast root to LexicalScopeNode (global scope)
    LexicalScopeNode* global_scope = static_cast<LexicalScopeNode*>(&root);
    
    // Allocate memory for global scope
    allocateScope(global_scope, true);
    
    // Walk the AST and generate code for all children (these are unique_ptr<ASTNode>)
    for (auto& child : global_scope->ASTNode::children) {
        generateNode(child.get(), global_scope);
    }
    
    // For now, just exit cleanly
    emitter.emitMovRAXImm64(60);  // sys_exit
    emitter.emitXorRdiRdi();      // exit code 0
    emitter.emitSyscall();
}

void Codegen::writeProgramToExecutable() {
    // Allocate executable memory
    void* exec_mem = mmap(nullptr, emitter.buffer.size(), 
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (exec_mem == MAP_FAILED) {
        std::cerr << "Failed to allocate executable memory" << std::endl;
        return;
    }
    
    // Copy machine code to executable memory
    std::memcpy(exec_mem, emitter.buffer.data(), emitter.buffer.size());
    
    // Execute the code
    typedef void (*func_ptr)();
    func_ptr func = reinterpret_cast<func_ptr>(exec_mem);
    func();
    
    // Clean up
    munmap(exec_mem, emitter.buffer.size());
}
