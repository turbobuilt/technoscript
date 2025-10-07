#pragma once
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <map>
#include <set>
#include <algorithm>
#include <stdexcept>

// Robustness limits to prevent infinite loops and hangs
namespace RobustnessLimits {
    constexpr int MAX_SCOPE_TRAVERSAL_DEPTH = 50;
    constexpr int MAX_AST_RECURSION_DEPTH = 1000;
    constexpr int MAX_PARSER_ITERATIONS = 10000;
    constexpr int MAX_ANALYSIS_ITERATIONS = 10000;
}

enum class AstNodeType {
    VAR_DECL, FUNCTION_DECL, FUNCTION_CALL, 
    IDENTIFIER, LITERAL, PRINT_STMT, GO_STMT, SETTIMEOUT_STMT, 
    AWAIT_EXPR, SLEEP_CALL, FOR_STMT, LET_DECL, 
    BINARY_EXPR, UNARY_EXPR, BLOCK_STMT,
    CLASS_DECL, NEW_EXPR, MEMBER_ACCESS, MEMBER_ASSIGN,
    METHOD_CALL, THIS_EXPR
};

enum class DataType { INT32, INT64, CLOSURE, PROMISE, OBJECT };

// Forward declarations
class FunctionDeclNode;
class LexicalScopeNode;
class ClassDeclNode;

// New structure for unified parameter information
struct ParameterInfo {
    int depth;                    // Scope depth  
    int offset;                   // Byte offset in parameter area
    LexicalScopeNode* scope;      // Pointer to the actual scope
    bool isHiddenParam;           // true for lexical scopes, false for regular params
    
    ParameterInfo(int d = 0, int o = 0, LexicalScopeNode* s = nullptr, bool hidden = false)
        : depth(d), offset(o), scope(s), isHiddenParam(hidden) {}
};

struct VariableInfo {
    DataType type;
    std::string name;
    int offset = 0;  // Offset from R15 where this variable/parameter is stored
    int size = 8;    // Size in bytes: 8 for regular vars, correct closure size for closures, calculated for objects
    LexicalScopeNode* definedIn = nullptr;
    FunctionDeclNode* funcNode = nullptr; // For closures: back-reference to function
    ClassDeclNode* classNode = nullptr; // For objects: pointer to class definition
};

// Shared packing utility for both lexical scopes and classes
namespace VariablePacking {
    // Get size for a type (without closure/object special handling)
    inline int getBaseTypeSize(DataType type) {
        switch (type) {
            case DataType::INT32: return 4;
            case DataType::INT64: return 8;
            case DataType::CLOSURE: return 8; // Base pointer size, actual size calculated elsewhere
            case DataType::PROMISE: return 8;
            case DataType::OBJECT: return 8; // Base pointer size, actual size calculated elsewhere
            default: return 8;
        }
    }
    
    // Pack a collection of variables, returns total size
    inline int packVariables(std::vector<VariableInfo*>& vars) {
        // Sort by size (biggest first) for optimal packing
        std::sort(vars.begin(), vars.end(), [](const VariableInfo* a, const VariableInfo* b) {
            return a->size > b->size;
        });
        
        int offset = 0;
        for (auto* var : vars) {
            int size = var->size;
            int align = (var->type == DataType::CLOSURE || var->type == DataType::OBJECT) ? 8 : size;
            offset = (offset + align - 1) & ~(align - 1); // Align
            var->offset = offset;
            offset += size;
        }
        
        // Return 8-byte aligned total size
        return (offset + 7) & ~7;
    }
}

// Structure to track closure creation and patching
struct ClosurePatchInfo {
    int scopeOffset;              // Offset in scope where closure is stored
    FunctionDeclNode* function;   // Function this closure points to
    LexicalScopeNode* scope;      // Scope where this closure is created
};



class ASTNode {
public:
    AstNodeType type;
    std::vector<std::unique_ptr<ASTNode>> children;
    std::string value;
    VariableInfo* varRef = nullptr; // For analysis phase
    
    ASTNode(AstNodeType t, const std::string& v = "") : type(t), value(v) {}
    virtual ~ASTNode() = default;
};

class LexicalScopeNode : public ASTNode {
public:
    std::map<std::string, VariableInfo> variables;
    LexicalScopeNode* parentFunctionScope;
    int depth;
    
    std::set<int> parentDeps;    // Parent scope depths this scope depends on
    std::set<int> descendantDeps; // Parent scope depths needed by descendants
    std::vector<int> allNeeded;     // Combined dependencies (parents first, then descendants, no duplicates)
    int totalSize = 0;              // Total packed size of this scope
    
    // For codegen: maps required depth -> parameter index in parent function
    // -1 means it's the immediate parent scope itself (stored in current scope)
    std::map<int, int> scopeDepthToParentParameterIndexMap;
    
    LexicalScopeNode(LexicalScopeNode* p = nullptr, int d = 0) : ASTNode(AstNodeType::FUNCTION_DECL), parentFunctionScope(p), depth(d) {
        // Parent pointers are set later by setupParentPointers() in analyzer
        // Note: type will be properly set by derived classes (e.g., FunctionDeclNode)
    }
    
    void updateAllNeeded() {
        allNeeded.clear();
        
        // Add parent deps first
        for (int depthIdx : parentDeps) {
            allNeeded.push_back(depthIdx);
        }
        
        // Add descendant deps that aren't already in parent deps
        for (int depthIdx : descendantDeps) {
            if (parentDeps.find(depthIdx) == parentDeps.end()) {
                allNeeded.push_back(depthIdx);
            }
        }
    }
    
    void buildScopeDepthToParentParameterIndexMap();

    int getParameterOffset(int index); // Declaration only, implementation after FunctionDeclNode
    
    void pack();

private:
    static int getTypeSize(const VariableInfo& var);
};

class VarDeclNode : public ASTNode {
public:
    std::string varName;
    DataType varType;
    std::string customTypeName; // For OBJECT type, the class name
    
    VarDeclNode(const std::string& name, DataType type, const std::string& customType = "") 
        : ASTNode(AstNodeType::VAR_DECL), varName(name), varType(type), customTypeName(customType) {}
};

class FunctionDeclNode : public LexicalScopeNode {
public:
    std::string funcName;
    std::vector<std::string> params;
    void* asmjitLabel = nullptr;   // asmjit::Label for this function (stored as void* to avoid header dependency)
    bool isMethod = false;          // Set to true if this is a class method
    ClassDeclNode* owningClass = nullptr; // Set if this is a method - points to the owning class
    
    // NEW: Unified parameter information - single source of truth for all parameter layout
    std::vector<VariableInfo> paramsInfo;        // Regular parameters with calculated offsets
    std::vector<ParameterInfo> hiddenParamsInfo; // Hidden scope parameters with calculated offsets
    
    FunctionDeclNode(const std::string& name, LexicalScopeNode* p = nullptr) 
        : LexicalScopeNode(p), funcName(name) {
        type = AstNodeType::FUNCTION_DECL;
        value = name;
    }
    
    // Helper methods for accessing unified parameter information
    int getParameterOffset(int index) const;
    ParameterInfo* findHiddenParam(int depth);
    const ParameterInfo* findHiddenParam(int depth) const;
    int getTotalRegularParamsSize() const;
};

class IdentifierNode : public ASTNode {
public:
    struct VariableAccess {
        bool inCurrentScope; // true if in current scope, false if in parent scope
        size_t scopeParameterIndex; // index in parent params (only valid if inCurrentScope is false)
        int offset; // Offset within the scope for the variable
    };
    
    LexicalScopeNode* accessedIn = nullptr; // Set during analysis: the scope where this identifier is accessed
    
    IdentifierNode(const std::string& name) : ASTNode(AstNodeType::IDENTIFIER, name) {}
    
    // any time this is accessed it could be in the current scope or in an ancestor scope. Ancestor scopes are passed as "hidden params" after actual params. This function tells us the absolute parameter index of that scope address, and the offset in it we can find this variable at.
    VariableAccess getVariableAccess() {
        if (!varRef) throw std::runtime_error("Variable not analyzed: " + value);
        if (!varRef->definedIn) throw std::runtime_error("Variable scope not found: " + value);
        if (!accessedIn) throw std::runtime_error("Variable access scope not set: " + value);
        
        LexicalScopeNode* definingScope = varRef->definedIn;
        
        if (definingScope == accessedIn) {
            return {true, 0, varRef->offset}; // inCurrentScope=true, scopeParameterIndex irrelevant
        } else {
            // Use the access method to get parameter index for the defining scope
            // check if it is a FunctionDeclNode, we handle those different than block scope
            if (accessedIn->type == AstNodeType::FUNCTION_DECL) {
                // cast to FunctionDeclNode
                auto funcDecl = static_cast<FunctionDeclNode*>(accessedIn);
                // get index in allneeded
                auto it = std::find(funcDecl->allNeeded.begin(), funcDecl->allNeeded.end(), definingScope->depth);
                if (it == funcDecl->allNeeded.end()) {
                    throw std::runtime_error("Scope depth not found in allNeeded: " + std::to_string(definingScope->depth));
                }
                auto hiddenIndex = std::distance(funcDecl->allNeeded.begin(), it);
                auto actualParameterIndex = funcDecl->paramsInfo.size() + hiddenIndex; // regular params + hidden param index
                
                return {false, actualParameterIndex, varRef->offset}; // inCurrentScope=false
            } else {
                // This is a block scope accessing a parent scope variable
                // Find the index of the defining scope depth in allNeeded
                auto blockScope = static_cast<LexicalScopeNode*>(accessedIn);
                auto it = std::find(blockScope->allNeeded.begin(), blockScope->allNeeded.end(), definingScope->depth);
                if (it == blockScope->allNeeded.end()) {
                    throw std::runtime_error("Scope depth not found in allNeeded for block: " + std::to_string(definingScope->depth));
                }
                auto scopeIndex = std::distance(blockScope->allNeeded.begin(), it);
                
                // For blocks, the parameter index is just the index in allNeeded
                // since blocks only have "hidden parameters" (parent scope pointers)
                return {false, static_cast<size_t>(scopeIndex), varRef->offset}; // inCurrentScope=false
            }
        }
    }
};

class LiteralNode : public ASTNode {
public:
    LiteralNode(const std::string& val) : ASTNode(AstNodeType::LITERAL, val) {}
};

class FunctionCallNode : public IdentifierNode {
public:
    std::vector<std::unique_ptr<ASTNode>> args;

    FunctionCallNode(const std::string& name) : IdentifierNode(name) {
        type = AstNodeType::FUNCTION_CALL;  // Override the type set by IdentifierNode
    }
};

class GoStmtNode : public ASTNode {
public:
    std::unique_ptr<FunctionCallNode> functionCall;
    
    GoStmtNode() : ASTNode(AstNodeType::GO_STMT) {}
};

class SetTimeoutStmtNode : public ASTNode {
public:
    std::unique_ptr<IdentifierNode> functionName;
    std::unique_ptr<ASTNode> delay; // LiteralNode for delay in milliseconds
    
    SetTimeoutStmtNode() : ASTNode(AstNodeType::SETTIMEOUT_STMT) {}
};

class AwaitExprNode : public ASTNode {
public:
    AwaitExprNode() : ASTNode(AstNodeType::AWAIT_EXPR) {}
};

class SleepCallNode : public ASTNode {
public:
    SleepCallNode() : ASTNode(AstNodeType::SLEEP_CALL) {}
};

class LetDeclNode : public ASTNode {
public:
    std::string varName;
    DataType varType;
    
    LetDeclNode(const std::string& name, DataType type) 
        : ASTNode(AstNodeType::LET_DECL), varName(name), varType(type) {}
};

class ForStmtNode : public LexicalScopeNode {
public:
    std::unique_ptr<ASTNode> init;      // initialization (e.g., let i = 0)
    std::unique_ptr<ASTNode> condition; // condition (e.g., i < 10)
    std::unique_ptr<ASTNode> update;    // update (e.g., ++i)
    // body statements are in the children vector inherited from ASTNode
    
    ForStmtNode(LexicalScopeNode* p = nullptr, int d = 0) 
        : LexicalScopeNode(p, d) {
        type = AstNodeType::FOR_STMT;
    }
};

class BlockStmtNode : public LexicalScopeNode {
public:
    // body statements are in the children vector inherited from ASTNode
    
    BlockStmtNode(LexicalScopeNode* p = nullptr, int d = 0) 
        : LexicalScopeNode(p, d) {
        type = AstNodeType::BLOCK_STMT;
    }
};

class BinaryExprNode : public ASTNode {
public:
    std::string operator_type; // "<", ">", "==", etc.
    std::unique_ptr<ASTNode> left;
    std::unique_ptr<ASTNode> right;
    
    BinaryExprNode(const std::string& op) 
        : ASTNode(AstNodeType::BINARY_EXPR), operator_type(op) {}
};

class UnaryExprNode : public ASTNode {
public:
    std::string operator_type; // "++", "--", etc.
    std::unique_ptr<ASTNode> operand;
    
    UnaryExprNode(const std::string& op) 
        : ASTNode(AstNodeType::UNARY_EXPR), operator_type(op) {}
};

// Class-related nodes
class ClassDeclNode : public ASTNode {
public:
    std::string className;
    
    // Inheritance support
    std::vector<std::string> parentClassNames;  // Names of parent classes (from parsing)
    std::vector<ClassDeclNode*> parentRefs;     // Resolved parent class pointers (from analysis)
    
    // Fields (only this class's own fields)
    std::map<std::string, VariableInfo> fields; // field name -> VariableInfo with offset, size, etc.
    
    // Methods as closures
    std::map<std::string, std::unique_ptr<FunctionDeclNode>> methods;
    
    // Layout information (computed during analysis)
    std::map<std::string, int> parentOffsets;   // parent class name -> offset in object layout
    std::vector<std::string> allFieldsInOrder;  // All fields (parents + own) in layout order
    
    // VTable information (build-time, converted to runtime ClassMetadata)
    struct VTableEntry {
        std::string methodName;
        FunctionDeclNode* method;  // Pointer to the method's FunctionDeclNode (build-time)
        int thisOffset;            // Offset adjustment needed for this pointer
        ClassDeclNode* definingClass; // Which class originally defined this method
        int closureSize = 0;       // Size of the closure for this method
        int closureOffsetInObject = 0; // Offset in object where this method's closure is stored
    };
    std::vector<VTableEntry> vtable;
    
    int totalMethodClosuresSize = 0;  // Total size of all method closures in object
    int totalSize = 0;                 // Total size of all fields (no header, no methods, just data)
    int totalObjectDataSize = 0;       // Total size including method closures + fields
    
    // Runtime metadata (generated after analysis, filled during codegen)
    void* runtimeMetadata = nullptr;  // Points to ClassMetadata structure
    
    ClassDeclNode(const std::string& name) 
        : ASTNode(AstNodeType::CLASS_DECL), className(name) {}
    
    // Pack class fields using the shared packing algorithm
    void pack() {
        std::vector<VariableInfo*> fieldVars;
        for (auto& [name, fieldInfo] : fields) {
            fieldVars.push_back(&fieldInfo);
        }
        
        totalSize = VariablePacking::packVariables(fieldVars);
        
        // Calculate method closure sizes and offsets
        totalMethodClosuresSize = 0;
        for (auto& entry : vtable) {
            // Closure layout: [func_addr(8)][size(8)][scope_ptr1(8)]...[scope_ptrN(8)]
            int closureSize = 16; // func_addr + size field
            if (entry.method && entry.method->allNeeded.size() > 0) {
                closureSize += entry.method->allNeeded.size() * 8;
            }
            entry.closureSize = closureSize;
            entry.closureOffsetInObject = totalMethodClosuresSize;
            totalMethodClosuresSize += closureSize;
        }
        
        // Total object data = method closures + fields
        totalObjectDataSize = totalMethodClosuresSize + totalSize;
        
        printf("DEBUG ClassDeclNode::pack: Class '%s' packed:\n", className.c_str());
        printf("  Method closures size: %d bytes\n", totalMethodClosuresSize);
        printf("  Fields size: %d bytes\n", totalSize);
        printf("  Total object data size: %d bytes\n", totalObjectDataSize);
        
        for (auto& entry : vtable) {
            printf("  Method '%s' closure at offset %d (size=%d)\n", 
                   entry.methodName.c_str(), entry.closureOffsetInObject, entry.closureSize);
        }
        
        for (const auto& [name, fieldInfo] : fields) {
            // Fields start after method closures
            int actualOffset = totalMethodClosuresSize + fieldInfo.offset;
            printf("  Field '%s' at offset %d (relative to fields start: %d, size=%d)\n", 
                   name.c_str(), actualOffset, fieldInfo.offset, fieldInfo.size);
        }
    }
};

class NewExprNode : public ASTNode {
public:
    std::string className;
    ClassDeclNode* classRef = nullptr; // Set during analysis
    
    NewExprNode(const std::string& name) 
        : ASTNode(AstNodeType::NEW_EXPR), className(name) {}
};

class MemberAccessNode : public ASTNode {
public:
    std::unique_ptr<ASTNode> object;  // The object being accessed (identifier or expression)
    std::string memberName;
    ClassDeclNode* classRef = nullptr; // Set during analysis
    int memberOffset = 0; // Byte offset of the field in the object
    
    MemberAccessNode(const std::string& member) 
        : ASTNode(AstNodeType::MEMBER_ACCESS), memberName(member) {}
};

class MemberAssignNode : public ASTNode {
public:
    std::unique_ptr<MemberAccessNode> member;
    std::unique_ptr<ASTNode> value;
    
    MemberAssignNode() : ASTNode(AstNodeType::MEMBER_ASSIGN) {}
};

// Method call node - for calling methods on objects
// Inherits from FunctionCallNode to reuse function call infrastructure
class MethodCallNode : public FunctionCallNode {
public:
    std::unique_ptr<ASTNode> object;            // The object expression (e.g., IdentifierNode for "dog")
    std::string methodName;                     // Name of the method to call
    // args is inherited from FunctionCallNode
    
    // Resolved during analysis
    FunctionDeclNode* resolvedMethod = nullptr; // The actual method function
    int vtableIndex = -1;                       // Index in the vtable
    int thisOffset = 0;                         // Offset to adjust this pointer
    ClassDeclNode* objectClass = nullptr;       // Class of the object
    int methodClosureOffset = 0;                // Offset in object where method closure is stored
    
    MethodCallNode(const std::string& method) 
        : FunctionCallNode(method), methodName(method) {
        type = AstNodeType::METHOD_CALL;  // Override to METHOD_CALL
    }
};

// This expression - represents 'this' keyword in methods
class ThisNode : public ASTNode {
public:
    ClassDeclNode* classContext = nullptr;  // Set during analysis - which class this method belongs to
    FunctionDeclNode* methodContext = nullptr; // The method this 'this' appears in
    
    ThisNode() : ASTNode(AstNodeType::THIS_EXPR) {
        value = "this";
    }
};

// Implementation of getTypeSize after all classes are defined
inline int LexicalScopeNode::getTypeSize(const VariableInfo& var) {
    // Use the precomputed size field for fast access
    return var.size;
}

// Implementation of buildScopeDepthToParentParameterIndexMap after all classes are defined
inline void LexicalScopeNode::buildScopeDepthToParentParameterIndexMap() {
    // Check if already processed - should only happen once per scope in single-pass analysis
    if (!scopeDepthToParentParameterIndexMap.empty()) {
        throw std::runtime_error("buildScopeDepthToParentParameterIndexMap called multiple times on same scope - analysis bug");
    }
    
    int currentParamCount = 0;
    if (this->type == AstNodeType::FUNCTION_DECL) {
        // Function scopes: map needed scopes to hidden parameters after regular parameters
        FunctionDeclNode* currentFunc = static_cast<FunctionDeclNode*>(this);
        currentParamCount = currentFunc->paramsInfo.size(); // Use unified parameter info
        printf("DEBUG buildScopeDepthToParentParameterIndexMap: Function '%s' has %d regular params, needs %zu scopes\n", currentFunc->funcName.c_str(), currentParamCount, allNeeded.size());
    } else if (this->type == AstNodeType::BLOCK_STMT) {
        currentParamCount = 0; // Block scopes have no regular parameters
    }

    
    // Build map based on what this scope needs
    int hiddenParamIndex = 0; // Counter for hidden parameters
    
    for (int neededDepth : allNeeded) {
        if (neededDepth == this->depth) {
            // Skip current scope - it shouldn't be in allNeeded
            continue;
        }
        
        // Check if this is the immediate parent scope (depth = current_depth - 1)
        if (neededDepth == this->depth - 1) {
            // Immediate parent scope - accessible via r14, not a parameter
            printf("DEBUG buildScopeDepthToParentParameterIndexMap: depth %d -> param index -1 (immediate parent)\n", neededDepth);
            scopeDepthToParentParameterIndexMap[neededDepth] = -1;
        } else {
            // Other ancestor scopes - passed as hidden parameters
            int paramIndex = currentParamCount + hiddenParamIndex;
            printf("DEBUG buildScopeDepthToParentParameterIndexMap: depth %d -> param index %d (regular params=%d + hidden offset=%d)\n", 
                    neededDepth, paramIndex, currentParamCount, hiddenParamIndex);
            scopeDepthToParentParameterIndexMap[neededDepth] = paramIndex;
            hiddenParamIndex++; // Only increment for actual hidden parameters
        }
    }
    
    printf("DEBUG buildScopeDepthToParentParameterIndexMap: Final map");
    for (const auto& [depth, paramIdx] : scopeDepthToParentParameterIndexMap) {
        printf("DEBUG:   depth %d -> param index %d\n", depth, paramIdx);
    }
    
    // Other scope types (like FOR_STMT) don't need parameter mapping for now
}

// Implementation of pack after all classes are defined
inline void LexicalScopeNode::pack() {
    std::vector<std::pair<std::string, VariableInfo*>> vars;
    std::vector<std::pair<std::string, VariableInfo*>> params;
    
    // For function scopes, separate parameters from regular variables
    if (this->type == AstNodeType::FUNCTION_DECL) {
        FunctionDeclNode* funcDecl = static_cast<FunctionDeclNode*>(this);
        
        // Clear the unified parameter info arrays
        funcDecl->paramsInfo.clear();
        funcDecl->hiddenParamsInfo.clear();
        
        // Separate parameters from regular variables
        for (auto& [name, var] : variables) {
            bool isParam = false;
            for (const std::string& paramName : funcDecl->params) {
                if (name == paramName) {
                    params.push_back({name, &var});
                    isParam = true;
                    break;
                }
            }
            if (!isParam) {
                vars.push_back({name, &var});
            }
        }
    } else {
        // For non-function scopes, all variables are regular variables
        for (auto& [name, var] : variables) {
            vars.push_back({name, &var});
        }
    }
    
    // Start at offset 16 to reserve first 8 bytes for flags and 8 bytes for metadata pointer
    int offset = 16;
    
    FunctionDeclNode* funcDecl = nullptr;
    
    if (this->type == AstNodeType::FUNCTION_DECL) {
        funcDecl = static_cast<FunctionDeclNode*>(this);
    } else if (this->type == AstNodeType::BLOCK_STMT) {
        // Block scopes have 0 regular parameters, only "hidden parameters" (parent scope pointers)
        printf("DEBUG pack: Block scope needs %zu parent scope pointers\n", allNeeded.size());
    }
    
    // Pack regular parameters first (only for functions)
    if (funcDecl) {
        std::vector<VariableInfo*> paramVars;
        for (auto& [name, var] : params) {
            paramVars.push_back(var);
        }
        
        // Use shared packing for parameters
        offset = VariablePacking::packVariables(paramVars);
        
        // Store in paramsInfo for unified access
        for (auto& [name, var] : params) {
            printf("DEBUG pack: Parameter '%s' assigned offset %d (size=%d)\n", name.c_str(), var->offset, var->size);
            funcDecl->paramsInfo.push_back(*var);
        }
    }
    
    // Pack hidden lexical scope parameters (shared logic for functions and blocks)
    if (this->type == AstNodeType::FUNCTION_DECL || this->type == AstNodeType::BLOCK_STMT) {
        for (int neededDepth : allNeeded) {
            if (neededDepth != this->depth) { // Don't count current scope as hidden parameter
                offset = (offset + 7) & ~7; // 8-byte align
                printf("DEBUG pack: %s scope pointer for depth %d assigned offset %d\n", 
                       (this->type == AstNodeType::FUNCTION_DECL) ? "Hidden parameter" : "Parent", 
                       neededDepth, offset);
                
                if (funcDecl) {
                    // For functions, store in hiddenParamsInfo
                    LexicalScopeNode* correspondingScope = nullptr;
                    ParameterInfo hiddenParam(neededDepth, offset, correspondingScope, true);
                    funcDecl->hiddenParamsInfo.push_back(hiddenParam);
                }
                
                offset += 8; // Each scope pointer takes 8 bytes
            }
        }
    }
    
    // Then pack regular variables after parameters using shared packing algorithm
    if (!vars.empty()) {
        std::vector<VariableInfo*> varPtrs;
        for (auto& [name, var] : vars) {
            varPtrs.push_back(var);
        }
        
        // Adjust offsets to account for parameters/hidden params that came before
        int startOffset = offset;
        int varsSize = VariablePacking::packVariables(varPtrs);
        
        // Adjust all variable offsets by the starting offset
        for (auto* var : varPtrs) {
            var->offset += startOffset;
            printf("DEBUG pack: Variable '%s' assigned offset %d (size=%d)\n", var->name.c_str(), var->offset, var->size);
        }
        
        offset = startOffset + varsSize;
    }
    
    // Ensure total size is 8-byte aligned and includes the 8-byte flags header
    totalSize = (offset + 7) & ~7;
    
    // Ensure minimum size is at least FLAGS_SIZE (8 bytes) even for empty scopes
    if (totalSize < 8) {
        totalSize = 8;
    }
}

// Implementation of FunctionDeclNode helper methods
inline int FunctionDeclNode::getParameterOffset(int index) const {
    if (index < 0) {
        throw std::runtime_error("Invalid parameter index: " + std::to_string(index));
    }
    
    if (index < (int)paramsInfo.size()) {
        // Regular parameter - use pre-calculated offset from paramsInfo
        return paramsInfo[index].offset;
    } else {
        // Hidden parameter - use pre-calculated offset from hiddenParamsInfo
        int hiddenIndex = index - (int)paramsInfo.size();
        if (hiddenIndex < (int)hiddenParamsInfo.size()) {
            return hiddenParamsInfo[hiddenIndex].offset;
        } else {
            throw std::runtime_error("Parameter index out of range: " + std::to_string(index));
        }
    }
}

inline ParameterInfo* FunctionDeclNode::findHiddenParam(int depth) {
    for (auto& param : hiddenParamsInfo) {
        if (param.depth == depth) {
            return &param;
        }
    }
    return nullptr;
}

inline const ParameterInfo* FunctionDeclNode::findHiddenParam(int depth) const {
    for (const auto& param : hiddenParamsInfo) {
        if (param.depth == depth) {
            return &param;
        }
    }
    return nullptr;
}

inline int FunctionDeclNode::getTotalRegularParamsSize() const {
    if (paramsInfo.empty()) {
        return 0;
    }
    
    // Return the end offset of the last parameter
    const auto& lastParam = paramsInfo.back();
    return lastParam.offset + lastParam.size;
}

// Implementation of LexicalScopeNode::getParameterOffset after FunctionDeclNode is defined
inline int LexicalScopeNode::getParameterOffset(int index) {
    // Delegate to FunctionDeclNode's unified parameter offset calculation
    if (this->type == AstNodeType::FUNCTION_DECL) {
        return static_cast<FunctionDeclNode*>(this)->getParameterOffset(index);
    } else {
        throw std::runtime_error("getParameterOffset called on non-function scope");
    }
}