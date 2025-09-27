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
    LEXICAL_SCOPE, VAR_DECL, FUNCTION_DECL, FUNCTION_CALL, 
    IDENTIFIER, LITERAL, PRINT_STMT, GO_STMT
};

enum class DataType { INT32, INT64, CLOSURE };

// Forward declarations
class FunctionDeclNode;
class LexicalScopeNode;

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
    int size = 8;    // Size in bytes: 8 for regular vars, correct closure size for closures
    LexicalScopeNode* definedIn = nullptr;
    FunctionDeclNode* funcNode = nullptr; // For closures: back-reference to function
};

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
    
    LexicalScopeNode(LexicalScopeNode* p = nullptr, int d = 0) : ASTNode(AstNodeType::LEXICAL_SCOPE), parentFunctionScope(p), depth(d) {
        // Parent pointers are set later by setupParentPointers() in analyzer
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
    
    VarDeclNode(const std::string& name, DataType type) 
        : ASTNode(AstNodeType::VAR_DECL), varName(name), varType(type) {}
};

class FunctionDeclNode : public LexicalScopeNode {
public:
    std::string funcName;
    std::vector<std::string> params;
    void* asmjitLabel = nullptr;   // asmjit::Label for this function (stored as void* to avoid header dependency)
    
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
                // throw for now
                // for block scope we will have pushed needed scope addresses onto stack.
                throw std::runtime_error("Variable in non-function parent scope not supported yet: " + value);
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
    
    // Only function scopes need parameter mapping
    if (this->type != AstNodeType::FUNCTION_DECL) return;
    
    
    // Get the current function's parameter count
    FunctionDeclNode* currentFunc = static_cast<FunctionDeclNode*>(this);
    int currentParamCount = currentFunc->paramsInfo.size(); // Use unified parameter info
    
    printf("DEBUG buildScopeDepthToParentParameterIndexMap: Function '%s' has %d regular params, needs %zu scopes\n", 
           currentFunc->funcName.c_str(), currentParamCount, allNeeded.size());
    
    // Build map based on what this scope needs
    // CRITICAL FIX: We need to filter out the current scope from allNeeded when assigning parameter indices
    int hiddenParamIndex = 0; // Counter for hidden parameters (excludes current scope)
    
    for (int neededDepth : allNeeded) {
        if (neededDepth == this->depth) {
            // this should throw an error that the current scope shouldn't be in allNeeded
            throw std::runtime_error("Current scope depth found in allNeeded - analysis bug");
        } else {
            // Scope parameters start after regular parameters
            int paramIndex = currentParamCount + hiddenParamIndex;
            printf("DEBUG buildScopeDepthToParentParameterIndexMap: depth %d -> param index %d (regular params=%d + hidden offset=%d)\n", 
                   neededDepth, paramIndex, currentParamCount, hiddenParamIndex);
            scopeDepthToParentParameterIndexMap[neededDepth] = paramIndex;
            hiddenParamIndex++; // Only increment for actual hidden parameters
        }
    }
    
    printf("DEBUG buildScopeDepthToParentParameterIndexMap: Final map for function '%s':\n", currentFunc->funcName.c_str());
    for (const auto& [depth, paramIdx] : scopeDepthToParentParameterIndexMap) {
        printf("DEBUG:   depth %d -> param index %d\n", depth, paramIdx);
    }
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
    
    // Sort regular variables by type size (biggest first)
    std::sort(vars.begin(), vars.end(), [](const auto& a, const auto& b) {
        return a.second->size > b.second->size;
    });
    
    int offset = 0;
    
    // For function scopes, first allocate space for parameters
    if (this->type == AstNodeType::FUNCTION_DECL) {
        FunctionDeclNode* funcDecl = static_cast<FunctionDeclNode*>(this);
        
        // 1. Pack regular parameters first and populate paramsInfo
        for (auto& [name, var] : params) {
            int size = var->size;
            int align = var->type == DataType::CLOSURE ? 8 : size; // Closures are pointer-aligned
            offset = (offset + align - 1) & ~(align - 1); // Align
            var->offset = offset;
            printf("DEBUG pack: Parameter '%s' assigned offset %d (size=%d)\n", name.c_str(), offset, size);
            
            // Store in paramsInfo for unified access
            funcDecl->paramsInfo.push_back(*var);
            
            offset += size; // Use actual parameter size
        }
        
        // 2. Pack hidden lexical scope parameters and populate hiddenParamsInfo
        for (int neededDepth : allNeeded) {
            if (neededDepth != this->depth) { // Don't count current scope as hidden parameter
                offset = (offset + 7) & ~7; // 8-byte align
                printf("DEBUG pack: Hidden parameter for depth %d assigned offset %d\n", neededDepth, offset);
                
                // Find the corresponding scope for this depth
                LexicalScopeNode* correspondingScope = nullptr;
                // We'll need to find this scope - for now we'll store null and fix in analysis
                
                ParameterInfo hiddenParam(neededDepth, offset, correspondingScope, true);
                funcDecl->hiddenParamsInfo.push_back(hiddenParam);
                
                offset += 8; // Each scope pointer takes 8 bytes
            }
        }
    }
    
    // Then pack regular variables after parameters
    for (auto& [name, var] : vars) {
        int size = var->size; // Use the size field instead of getTypeSize
        int align = var->type == DataType::CLOSURE ? 8 : size; // Closures are pointer-aligned
        offset = (offset + align - 1) & ~(align - 1); // Align
        var->offset = offset;
        printf("DEBUG pack: Variable '%s' assigned offset %d (size=%d)\n", name.c_str(), offset, size);
        offset += size;
    }
    
    // Ensure total size is 8-byte aligned
    totalSize = (offset + 7) & ~7;
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