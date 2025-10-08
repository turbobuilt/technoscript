# Function Registry Implementation

## Overview
Implemented a function registry system to avoid multiple traversals through the AST during code generation. This improves compilation efficiency and simplifies the code generation process.

## Changes Made

### 1. Parser Updates (`parser.h`, `parser.cpp`)

#### Added Function Registry
- **New field**: `std::vector<FunctionDeclNode*> functionRegistry`
- **Purpose**: Collects all functions (including class methods) during parsing

#### Registration Points
1. **Regular functions** - Registered in `parseFunctionDecl()`:
   ```cpp
   functionRegistry.push_back(func.get());
   ```

2. **Class methods** - Registered in `parseClassDecl()`:
   ```cpp
   functionRegistry.push_back(method.get());
   ```

3. **Main function** - Registered in `parse()`:
   ```cpp
   functionRegistry.push_back(root.get());
   ```

#### New Public Method
```cpp
const std::vector<FunctionDeclNode*>& getFunctionRegistry() const;
```

### 2. Code Generator Updates (`codegen.h`, `codegen.cpp`)

#### Modified Signatures
- `CodeGenerator::generateCode()` - Now accepts `functionRegistry` parameter
- `Codegen::generateProgram()` - Now accepts `functionRegistry` parameter

#### Two-Pass Code Generation

**First Pass: Generate All Functions**
```cpp
void CodeGenerator::generateAllFunctions(const std::vector<FunctionDeclNode*>& functionRegistry)
```
- Creates labels for all functions upfront
- Generates actual code for all functions (including methods)
- Processes function bodies (skipping nested functions/classes)
- All functions are emitted sequentially in memory

**Second Pass: Traverse AST Normally**
```cpp
void CodeGenerator::generateProgram(ASTNode* root)
```
- Processes the main AST structure
- Classes are handled to set up metadata
- Function declarations just create closures (code already generated)

#### Modified Function Declaration Handling
`generateFunctionDecl()` now only creates closures during AST traversal:
- Function code is already generated from the registry
- Only stores function addresses in closures at the current scope
- No recursive function generation

#### Modified Class Declaration Handling
`generateClassDecl()` now only validates metadata:
- Method code is already generated from the registry
- Verifies labels and closures exist
- Actual function address patching happens in `patchMetadataClosures()`

### 3. Main Program Update (`main.cpp`)
Updated to pass function registry to code generator:
```cpp
codeGen.generateProgram(*ast, parser.getClassRegistry(), parser.getFunctionRegistry());
```

## Benefits

### 1. Single Traversal
- Functions are generated exactly once during the first pass
- No duplicate code generation
- No need to traverse nested function trees multiple times

### 2. Predictable Memory Layout
- All functions are laid out sequentially in memory
- Labels are created upfront before any code generation
- Forward references are properly resolved

### 3. Class Methods Properly Handled
- Methods maintain reference to their owning class via `FunctionDeclNode::owningClass`
- Method closures are created in class metadata
- Method code is generated early, closure addresses patched later

### 4. Cleaner Separation of Concerns
- **Parsing**: Collects all functions
- **First Pass**: Generates all function code
- **Second Pass**: Handles AST structure and creates closures

## Implementation Details

### Function Registry Structure
Each entry in the registry is a `FunctionDeclNode*` pointer that includes:
- Function name and parameters
- `isMethod` flag indicating if it's a class method
- `owningClass` pointer for methods (links method to its class)
- `asmjitLabel` for the generated code location

### Method-Class Linkage
Methods maintain a reference to their class:
```cpp
struct FunctionDeclNode {
    bool isMethod = false;
    ClassDeclNode* owningClass = nullptr;
    // ...
};
```

This ensures that during code generation, methods have access to their class context without needing to traverse the class hierarchy.

### Closure Creation
During the second pass (AST traversal):
1. **Inline functions**: Closures created when var declarations are processed
2. **Class methods**: Method closures stored in class metadata, patched after code commit

## Testing
The implementation was tested with class methods that use `this`:
```javascript
class Animal {
    age: int64;
    printAge() {
        print(this.age);
    }
}
var a: Animal = new Animal();
a.printAge();
```

Output shows the two-pass approach working correctly:
```
=== First Pass: Generating All Functions ===
Generating 2 functions from registry
...
Finished generating all functions from registry

=== Second Pass: Generating Main Program ===
...
```

## Future Improvements
1. Could optimize function ordering based on call graph
2. Could add function inlining hints based on registry analysis
3. Could parallelize function code generation (independent functions)
