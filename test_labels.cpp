#include <iostream>
#include <asmjit/asmjit.h>

using namespace asmjit;

extern "C" void print_int64(int64_t value) {
    std::cout << "Value: " << value << std::endl;
}

int main() {
    JitRuntime rt;
    CodeHolder code;
    
    code.init(rt.environment(), rt.cpuFeatures());
    x86::Builder cb(&code);
    
    // Create a label for a function
    Label funcLabel = cb.newLabel();
    
    // Test 1: Can we store a label address in memory?
    cb.mov(x86::rdi, 64);  // malloc size
    cb.mov(x86::rax, reinterpret_cast<uint64_t>(malloc));
    cb.call(x86::rax);
    cb.mov(x86::r15, x86::rax);  // scope pointer
    
    // Try to store function label address - the way your code does it
    cb.mov(x86::ptr(x86::r15, 0), funcLabel);
    
    // Test 2: Can we call through the stored label?
    cb.mov(x86::rdi, 42);  // argument
    cb.call(x86::ptr(x86::r15, 0));  // call through stored pointer
    
    cb.mov(x86::eax, 0);
    cb.ret();
    
    // Now bind the function label
    cb.bind(funcLabel);
    cb.push(x86::rbp);
    cb.mov(x86::rbp, x86::rsp);
    
    // Call print_int64
    cb.mov(x86::rax, reinterpret_cast<uint64_t>(print_int64));
    cb.call(x86::rax);
    
    cb.mov(x86::rsp, x86::rbp);
    cb.pop(x86::rbp);
    cb.ret();
    
    cb.finalize();
    
    void* executableFunc;
    Error err = rt.add(&executableFunc, &code);
    if (err) {
        std::cout << "AsmJit Error: " << DebugUtils::errorAsString(err) << std::endl;
        return 1;
    }
    
    typedef int (*MainFunc)();
    MainFunc func = reinterpret_cast<MainFunc>(executableFunc);
    
    std::cout << "About to execute..." << std::endl;
    int result = func();
    std::cout << "Result: " << result << std::endl;
    
    return 0;
}