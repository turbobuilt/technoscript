#include <iostream>
#include <iomanip>

int main() {
    // Generate mov rcx, r15 instruction
    uint8_t bytes[4];
    
    __asm__ volatile (
        "mov %%r15, %%rcx\n\t"
        : // no outputs
        : // no inputs  
        : "rcx" // clobbers
    );
    
    // This won't work since we can't capture the encoding, 
    // but let's just manually test what objdump shows for mov rcx, r15
    return 0;
}
