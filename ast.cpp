#include "ast.h"
#include <stdexcept>

int LexicalScopeNode::getParameterOffset(int index) {
    if (this->type != NodeType::FUNCTION_DECL) {
        throw std::runtime_error("getParameterOffset called on non-function scope");
    }
    
    FunctionDeclNode* funcDecl = static_cast<FunctionDeclNode*>(this);
    int offset = 0;
    
    // Sum up sizes of regular parameters up to the target index
    for (int i = 0; i < index && i < (int)funcDecl->params.size(); i++) {
        const std::string& paramName = funcDecl->params[i];
        auto it = this->variables.find(paramName);
        if (it != this->variables.end()) {
            offset += it->second.size;
        }
    }
    
    // If index is beyond regular parameters, add sizes of hidden scope parameters
    if (index >= (int)funcDecl->params.size()) {
        // Each hidden scope parameter is 8 bytes
        int hiddenParamIndex = index - funcDecl->params.size();
        offset += hiddenParamIndex * 8;
    }
    
    return offset;
}
