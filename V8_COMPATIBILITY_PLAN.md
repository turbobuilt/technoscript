# V8 API Compatibility Implementation Plan

## Goal
Make TechnoScript provide a V8-compatible C++ API so applications can link against `libtechnoscript` instead of `libv8`.

## Phase 1: Core Infrastructure (Week 1-2)

### A. Create v8.h Header Structure
```cpp
namespace v8 {
  class Isolate;
  class Context;
  class HandleScope;
  template<typename T> class Local;
  template<typename T> class Persistent;
  // ... etc
}
```

### B. Map V8 Concepts to TechnoScript
- **Isolate** → Your runtime/VM instance (one per thread)
- **Context** → Your LexicalScopeNode (execution environment)
- **Local handles** → Smart pointers to your runtime values
- **HandleScope** → RAII scope manager for handles

### C. Implement Basic Types
1. `v8::Isolate`
   - `Isolate::New()` - Create new VM instance
   - `Isolate::Dispose()` - Clean up
   - `Isolate::GetCurrent()` - Thread-local storage
   - `Isolate::Enter()/Exit()` - Context switching

2. `v8::HandleScope`
   - Constructor/Destructor for RAII
   - Track handles in current scope
   - Clean up when scope exits

3. `v8::Local<T>`
   - Template wrapper around internal pointers
   - Automatic handle scope management
   - `IsEmpty()`, `Clear()` methods

## Phase 2: Value System (Week 3-4)

### A. Value Hierarchy
```
Value
├── Primitive
│   ├── String
│   ├── Number
│   │   ├── Integer
│   │   │   └── Int32
│   │   └── Number (double)
│   ├── Boolean
│   ├── Undefined
│   └── Null
└── Object
    ├── Array
    ├── Function
    └── External
```

### B. Implement Each Type
1. **v8::String**
   - `String::NewFromUtf8()` - Create strings
   - `String::Utf8Value` - Convert to C string
   - Internal: Store as TechnoScript string objects

2. **v8::Number/Integer**
   - `Number::New()` - Create number
   - `Int32Value()`, `NumberValue()` - Extract values
   - Internal: Map to your int64 type

3. **v8::Object**
   - `Object::New()` - Create object
   - `Object::Set(key, value)` - Set property
   - `Object::Get(key)` - Get property
   - Internal: Map to your class instances

4. **v8::Function**
   - `Function::New()` - Create from C++ callback
   - `Function::Call()` - Invoke function
   - Internal: Wrap your JIT-compiled functions

## Phase 3: Context & Script Execution (Week 5-6)

### A. Context Management
```cpp
class Context {
public:
  static Local<Context> New(Isolate* isolate,
                           ExtensionConfiguration* extensions = nullptr,
                           Local<ObjectTemplate> global_template = Local<ObjectTemplate>(),
                           Local<Value> global_object = Local<Value>());
  void Enter();
  void Exit();
  Local<Object> Global();
  Isolate* GetIsolate();
  
  // Internal: Wraps your LexicalScopeNode
};
```

### B. Script Compilation & Execution
```cpp
class Script {
public:
  static Local<Script> Compile(Local<String> source);
  Local<Value> Run();
  
  // Internal: 
  // - Parse source with your Parser
  // - Analyze with your Analyzer
  // - Generate code with your Codegen
  // - Return wrapped result
};
```

### C. Integration Points
- Hook your parser to parse JavaScript (not just TechnoScript syntax)
- Map V8 API calls to your codegen
- Wrap return values in V8 handles

## Phase 4: Templates (Week 7-8)

### A. FunctionTemplate
```cpp
class FunctionTemplate {
public:
  static Local<FunctionTemplate> New(Isolate* isolate,
                                     FunctionCallback callback);
  Local<Function> GetFunction(Local<Context> context);
  Local<ObjectTemplate> PrototypeTemplate();
  void SetClassName(Local<String> name);
  
  // Internal: Store C++ callback, generate wrapper
};
```

### B. ObjectTemplate
```cpp
class ObjectTemplate {
public:
  static Local<ObjectTemplate> New(Isolate* isolate);
  void Set(Local<Name> name, Local<Data> value);
  void SetAccessor(Local<Name> name,
                   AccessorGetterCallback getter,
                   AccessorSetterCallback setter);
  void SetInternalFieldCount(int count);
  Local<Object> NewInstance(Local<Context> context);
  
  // Internal: Blueprint for creating objects
};
```

### C. Callbacks
```cpp
using FunctionCallback = void (*)(const FunctionCallbackInfo<Value>& info);
using AccessorGetterCallback = void (*)(Local<String> property,
                                        const PropertyCallbackInfo<Value>& info);
using AccessorSetterCallback = void (*)(Local<String> property,
                                        Local<Value> value,
                                        const PropertyCallbackInfo<void>& info);
```

## Phase 5: Exception Handling (Week 9)

### A. TryCatch
```cpp
class TryCatch {
public:
  explicit TryCatch(Isolate* isolate);
  ~TryCatch();
  
  bool HasCaught() const;
  Local<Value> Exception() const;
  Local<Message> Message() const;
  void Reset();
  
  // Internal: Catch exceptions from your runtime
};
```

### B. Exception Throwing
```cpp
class Exception {
public:
  static Local<Value> Error(Local<String> message);
  static Local<Value> TypeError(Local<String> message);
  static Local<Value> RangeError(Local<String> message);
};
```

## Phase 6: Advanced Features (Week 10+)

### A. Persistent Handles
```cpp
template<typename T>
class Persistent {
public:
  Persistent();
  Persistent(Isolate* isolate, Local<T> that);
  void Reset();
  void Reset(Isolate* isolate, const Local<T>& other);
  Local<T> Get(Isolate* isolate);
  
  // Internal: Reference counting or GC root
};
```

### B. Accessors & Interceptors
- Named property handlers
- Indexed property handlers
- Property interceptors

### C. External Resources
```cpp
class External {
public:
  static Local<External> New(Isolate* isolate, void* value);
  void* Value() const;
  
  // Internal: Wrap C++ pointers safely
};
```

## Implementation Checklist

### Minimal Viable V8 API (Hello World Compatible)
- [ ] `v8::Isolate::New()`, `GetCurrent()`
- [ ] `v8::HandleScope` (constructor/destructor)
- [ ] `v8::Local<T>` template
- [ ] `v8::Context::New()`, `Enter()`, `Exit()`
- [ ] `v8::String::NewFromUtf8()`
- [ ] `v8::Script::Compile()`, `Run()`
- [ ] `v8::Value` base class
- [ ] Basic GC integration

### Core Types (for real usage)
- [ ] `v8::Object` with Get/Set
- [ ] `v8::Number`, `v8::Integer`, `v8::Int32`
- [ ] `v8::Boolean`
- [ ] `v8::Array`
- [ ] `v8::Function` with Call()
- [ ] `v8::Undefined()`, `v8::Null()`

### Templates (for C++ bindings)
- [ ] `v8::FunctionTemplate`
- [ ] `v8::ObjectTemplate`
- [ ] `v8::FunctionCallback` support
- [ ] `v8::PropertyCallbackInfo`
- [ ] Internal fields

### Exception Handling
- [ ] `v8::TryCatch`
- [ ] `v8::Exception::Error()`
- [ ] Stack traces

### Advanced
- [ ] `v8::Persistent<T>`, `v8::UniquePersistent<T>`
- [ ] Property accessors
- [ ] Interceptors
- [ ] `v8::External`
- [ ] Security tokens

## File Structure

```
technoscript/
├── include/
│   └── v8/
│       ├── v8.h                    # Main header
│       ├── v8-isolate.h
│       ├── v8-context.h
│       ├── v8-handle-scope.h
│       ├── v8-local.h
│       ├── v8-value.h
│       ├── v8-primitive.h
│       ├── v8-object.h
│       ├── v8-function.h
│       ├── v8-template.h
│       └── v8-script.h
├── src/
│   ├── v8/
│   │   ├── isolate.cpp
│   │   ├── context.cpp
│   │   ├── handle-scope.cpp
│   │   ├── string.cpp
│   │   ├── object.cpp
│   │   ├── function.cpp
│   │   ├── script.cpp
│   │   └── template.cpp
│   └── [existing TechnoScript files]
└── Makefile                        # Build libtechnoscript.so

```

## Testing Strategy

### 1. V8 Hello World
Compile the official V8 hello-world.cc against your headers:
```cpp
#include "v8/v8.h"

int main() {
  v8::Isolate* isolate = v8::Isolate::New();
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::Context> context = v8::Context::New(isolate);
  v8::Context::Scope context_scope(context);
  
  v8::Local<v8::String> source = 
    v8::String::NewFromUtf8(isolate, "'Hello' + ', World!'");
  v8::Local<v8::Script> script = v8::Script::Compile(source);
  v8::Local<v8::Value> result = script->Run();
  
  v8::String::Utf8Value utf8(result);
  printf("%s\n", *utf8);
  
  isolate->Dispose();
  return 0;
}
```

### 2. Incremental Testing
- Test each class in isolation
- Build up complexity gradually
- Compare behavior with real V8

### 3. Real-World Tests
- Try compiling Node.js addons
- Test Chromium bindings
- Run V8 benchmark suite

## Next Steps

1. **Start with minimal API** - Get hello world working
2. **Expand type system** - Add all value types
3. **JavaScript parser** - Either:
   - Integrate existing JS parser (e.g., QuickJS parser)
   - Write JS parser from scratch
   - Use your parser but extend syntax
4. **Template system** - Enable C++ bindings
5. **Performance** - Optimize JIT, GC integration
6. **Compatibility testing** - Real applications

## Key Challenges

1. **JavaScript Semantics**: Your language is simpler than JS
   - Need full JS type system
   - Prototypes, closures, hoisting
   - Type coercion rules

2. **API Surface**: V8 API is huge
   - Start with essentials
   - Implement on-demand
   - Document differences

3. **Performance**: V8 is highly optimized
   - Your JIT is basic
   - Need better optimization passes
   - GC performance critical

4. **Testing**: Ensure compatibility
   - Automated test suite
   - Real-world applications
   - Performance benchmarks

## Success Metrics

- [ ] Compile V8 hello-world.cc successfully
- [ ] Execute JavaScript code
- [ ] C++ callbacks work
- [ ] Simple Node.js addon compiles
- [ ] Pass basic V8 API tests
- [ ] Performance within 10x of V8 (initial goal)
