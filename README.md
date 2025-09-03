# TechnoScript AST

A compact AST implementation for a new language design with JavaScript-inspired scoping.

## Features

- **LexicalScopeNode**: Root and function scopes with variable maps
- **Variable Resolution**: Cross-scope variable references with depth tracking
- **Goroutines**: `go` statement for concurrent execution
- **Simple Types**: Only int64 for reduced complexity

## Usage

```bash
make
./technoscript
```

## Language Syntax

```javascript
var x: int64 = 0;
function test() {
    var y: int64 = 10;
    print("hello world", x, y)  // x resolves from depth 1, y from depth 2
}
test()

go test()  // goroutine execution
```

## Architecture

- **ast.h**: AST node definitions with LexicalScopeNode containing variable maps
- **parser.cpp**: Tokenizer and recursive descent parser
- **analyzer.cpp**: Two-phase analysis for scope resolution
- **main.cpp**: Test driver showing scope depth resolution

The analyzer sets up parent pointers and resolves variable references to their defining scope depth.
# technoscript
