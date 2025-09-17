#pragma once
#include "ast.h"
#include "library.h"
#include "debugger.h"
#include <unordered_map>
#include <sys/mman.h>
#include <capstone/capstone.h>
#include <asmjit/asmjit.h>

// Enum for commonly used registers
enum class Register {
    RAX = 0,
    RCX = 1,
    RDX = 2,
    RBX = 3,
    RSP = 4,
    RBP = 5,
    RSI = 6,
    RDI = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15
};

// Structure to track function address patches
struct FunctionPatch {
    asmjit::Label label;         // AsmJit label for the function
    FunctionDeclNode* func;      // Function node to bind the label to
    size_t string_offset;        // For string patches: offset of string in buffer
    bool is_string_patch;        // True if this is a string address patch, false for function patch
    
    // Constructor for function patches
    FunctionPatch(asmjit::Label lbl, FunctionDeclNode* f) 
        : label(lbl), func(f), string_offset(0), is_string_patch(false) {}
    
    // Constructor for string patches  
    FunctionPatch(asmjit::Label lbl, FunctionDeclNode* f, size_t str_offset, bool is_str)
        : label(lbl), func(f), string_offset(str_offset), is_string_patch(is_str) {}
};

class Codegen {
private:
    asmjit::JitRuntime rt;
    asmjit::CodeHolder code;
    asmjit::x86::Assembler a;
    std::vector<uint8_t> buffer;
    std::unordered_map<std::string, uint64_t> extern_function_addresses;
    std::vector<FunctionPatch> function_patches; // Patches to apply later
    std::unordered_map<FunctionDeclNode*, asmjit::Label> function_labels; // Map functions to labels
    
    // Initialize external function addresses
    void initExternFunctions();
    
    // Allocate memory for lexical scope - returns instruction length
    size_t allocateScope(LexicalScopeNode* scope, bool is_global = false);
    
    // Unified scope setup (allocate + create closures) - returns instruction length
    size_t setupScope(LexicalScopeNode* scope, bool is_global = false);
    
    // Restore previous lexical scope - returns instruction length
    size_t restoreScope();
    
    // Create closures in the current scope - returns instruction length
    size_t createClosures(LexicalScopeNode* scope);
    
    // Patch all function addresses before execution
    void patchFunctionAddresses();
    
    // Walk AST and generate code for nodes
    size_t generateNode(ASTNode* node, LexicalScopeNode* current_scope);
    size_t generateVarDecl(VarDeclNode* node, LexicalScopeNode* current_scope);
    size_t generateLiteral(LiteralNode* node);
    size_t generatePrintStatement(ASTNode* node, LexicalScopeNode* current_scope);
    size_t generateIdentifier(IdentifierNode* node);
    size_t generateClosureCall(FunctionCallNode* node, LexicalScopeNode* current_scope);
    
    // Helper to load any variable into a specified register
    // This provides much more flexibility for register allocation and reduces unnecessary moves
    size_t loadVariableIntoRegister(IdentifierNode* identifier, Register target_reg);
    
    // Helper to load the defining scope address of a variable into a specified register
    // If the variable is in current scope (-1), loads r15. Otherwise loads the parent scope address.
    size_t loadVariableDefiningScopeAddressIntoRegister(IdentifierNode* identifier, Register target_reg);
    
    // Disassembly helper
    void disassembleCode(const std::vector<uint8_t>& code, uint64_t base_address = 0);
    
public:
    void generateProgram(ASTNode& root);
    void writeProgramToExecutable();
    void runWithUnicornDebugger();
    
    // Get the raw machine code
    const std::vector<uint8_t>& getCode() const { return buffer; }
};
