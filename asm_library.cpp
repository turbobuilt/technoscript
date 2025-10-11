#include "asm_library.h"
#include <cstdlib>
#include <cstring>

AsmLibrary::AsmLibrary(x86::Builder& builder_ref, x86::Gp scope_reg) 
    : builder(builder_ref), scopeReg(scope_reg) {
    // Create labels for utility functions
    resizeListLabel = builder.newLabel();
    compactListLabel = builder.newLabel();
    callocLabel = builder.newLabel();
    addToSafeListLabel = builder.newLabel();
    removeFromSafeListLabel = builder.newLabel();
}

void AsmLibrary::initializeExternalFunctions() {
    externalFunctions["calloc"] = (void*)calloc;
    externalFunctions["free"] = (void*)free;
    
    // Bind external function labels to their addresses
    builder.bind(callocLabel);
    builder.mov(x86::rax, (uint64_t)calloc);
}

void AsmLibrary::makeSafeUnorderedList(x86::Gp addressReg, x86::Gp offsetReg, int32_t initialSize) {
    // Calculate total size needed: metadata (32 bytes) + data (initialSize * 8 bytes)
    int32_t totalSize = 32 + (initialSize * 8);
    
    // Call calloc(1, totalSize)
    builder.mov(x86::rdi, 1);
    builder.mov(x86::rsi, totalSize);
    builder.mov(x86::rax, (uint64_t)calloc);
    builder.call(x86::rax);
    
    // Store the allocated pointer at [addressReg + offsetReg]
    builder.mov(x86::ptr(addressReg, offsetReg), x86::rax);
    
    // Initialize metadata
    // Lock = 0 (unlocked)
    builder.mov(x86::qword_ptr(x86::rax, SAFELIST_LOCK_OFFSET), 0);
    
    // Length = initialSize
    builder.mov(x86::qword_ptr(x86::rax, SAFELIST_LENGTH_OFFSET), initialSize);
    
    // Next available = 0
    builder.mov(x86::qword_ptr(x86::rax, SAFELIST_NEXT_OFFSET), 0);
    
    // Used slots = 0
    builder.mov(x86::qword_ptr(x86::rax, SAFELIST_USED_OFFSET), 0);
}

void AsmLibrary::addToSafeList(x86::Gp addressReg, x86::Gp offsetReg, x86::Gp valueReg, AsmFunctionType type) {
    if (type == AsmFunctionType::CALL) {
        // Call the pre-defined function
        builder.mov(x86::rdi, addressReg);
        builder.mov(x86::rsi, offsetReg);
        builder.mov(x86::rdx, valueReg);
        builder.call(addToSafeListLabel);
        return;
    }
    
    // Inline implementation
    // Load list pointer into r11
    builder.mov(x86::r11, x86::ptr(addressReg, offsetReg));
    
    // Spin lock
    emitSpinLock(x86::r11);
    
    // Load next_available index
    builder.mov(x86::r10, x86::qword_ptr(x86::r11, SAFELIST_NEXT_OFFSET));
    
    // Load length for bounds check
    builder.mov(x86::r9, x86::qword_ptr(x86::r11, SAFELIST_LENGTH_OFFSET));
    
    // Check if we need to resize (next_available >= length)
    builder.cmp(x86::r10, x86::r9);
    Label no_resize = builder.newLabel();
    builder.jl(no_resize);
    
    // Need to resize - call resize function
    builder.mov(x86::rdi, addressReg);  // Pass address register
    builder.mov(x86::rsi, offsetReg);   // Pass offset register
    builder.call(resizeListLabel);
    
    // Reload list pointer after resize
    builder.mov(x86::r11, x86::ptr(addressReg, offsetReg));
    builder.mov(x86::r10, x86::qword_ptr(x86::r11, SAFELIST_NEXT_OFFSET));
    
    builder.bind(no_resize);
    
    // Store value at data[next_available]
    builder.mov(x86::qword_ptr(x86::r11, x86::r10, 3, SAFELIST_DATA_OFFSET), valueReg);
    
    // Increment next_available
    builder.inc(x86::r10);
    builder.mov(x86::qword_ptr(x86::r11, SAFELIST_NEXT_OFFSET), x86::r10);
    
    // Increment used_slots
    builder.inc(x86::qword_ptr(x86::r11, SAFELIST_USED_OFFSET));
    
    // Unlock
    emitUnlock(x86::r11);
}

void AsmLibrary::removeFromSafeList(x86::Gp addressReg, x86::Gp offsetReg, x86::Gp indexReg, AsmFunctionType type) {
    if (type == AsmFunctionType::CALL) {
        // Call the pre-defined function
        builder.mov(x86::rdi, addressReg);
        builder.mov(x86::rsi, offsetReg);
        builder.mov(x86::rdx, indexReg);
        builder.call(removeFromSafeListLabel);
        return;
    }
    
    // Inline implementation
    // Load list pointer
    builder.mov(x86::r11, x86::ptr(addressReg, offsetReg));
    
    // Spin lock
    emitSpinLock(x86::r11);
    
    // Bounds check
    builder.mov(x86::r10, x86::qword_ptr(x86::r11, SAFELIST_NEXT_OFFSET));
    builder.cmp(indexReg, x86::r10);
    Label bounds_ok = builder.newLabel();
    builder.jl(bounds_ok);
    
    // Index out of bounds - unlock and return
    emitUnlock(x86::r11);
    Label end = builder.newLabel();
    builder.jmp(end);
    
    builder.bind(bounds_ok);
    
    // Zero out the data at index
    builder.mov(x86::qword_ptr(x86::r11, indexReg, 3, SAFELIST_DATA_OFFSET), 0);
    
    // Decrement used_slots
    builder.dec(x86::qword_ptr(x86::r11, SAFELIST_USED_OFFSET));
    
    // Unlock
    emitUnlock(x86::r11);
    
    builder.bind(end);
}

void AsmLibrary::compactSafeList(x86::Gp addressReg, x86::Gp offsetReg, AsmFunctionType type) {
    if (type == AsmFunctionType::CALL) {
        // Set up parameters and call the compact function
        builder.mov(x86::rdi, addressReg);
        builder.mov(x86::rsi, offsetReg);
        builder.call(compactListLabel);
    } else {
        // Inline implementation would be quite large, so we'll always call the function
        compactSafeList(addressReg, offsetReg, AsmFunctionType::CALL);
    }
}

void AsmLibrary::emitResizeListFunction() {
    builder.bind(resizeListLabel);
    
    // No function prologue needed - using only caller-saved registers
    
    // Parameters: rdi = addressReg, rsi = offsetReg
    // Load current list pointer
    builder.mov(x86::r8, x86::ptr(x86::rdi, x86::rsi));  // r8 = current list pointer
    
    // Load current length and calculate new length (4x)
    builder.mov(x86::rax, x86::qword_ptr(x86::r8, SAFELIST_LENGTH_OFFSET));
    builder.shl(x86::rax, 2);  // Multiply by 4
    builder.mov(x86::r9, x86::rax);  // r9 = new length
    
    // Calculate new total size: 32 + (new_length * 8)
    builder.shl(x86::rax, 3);  // Multiply by 8
    builder.add(x86::rax, 32);
    
    // Save registers before calloc
    builder.push(x86::rdi);   // Save addressReg
    builder.push(x86::rsi);   // Save offsetReg
    builder.push(x86::r8);    // Save current list pointer
    builder.push(x86::r9);    // Save new length
    
    // Allocate new memory
    builder.mov(x86::rdi, 1);
    builder.mov(x86::rsi, x86::rax);
    builder.mov(x86::rax, (uint64_t)calloc);
    builder.call(x86::rax);
    
    // Restore registers
    builder.pop(x86::r9);     // Restore new length
    builder.pop(x86::r8);     // Restore current list pointer
    builder.pop(x86::rsi);    // Restore offsetReg
    builder.pop(x86::rdi);    // Restore addressReg
    
    // New list pointer in rax
    builder.mov(x86::r10, x86::rax);  // r10 = new list pointer
    
    // Copy metadata
    builder.mov(x86::rcx, x86::qword_ptr(x86::r8, SAFELIST_LOCK_OFFSET));
    builder.mov(x86::qword_ptr(x86::r10, SAFELIST_LOCK_OFFSET), x86::rcx);
    
    builder.mov(x86::qword_ptr(x86::r10, SAFELIST_LENGTH_OFFSET), x86::r9);  // New length
    
    builder.mov(x86::rcx, x86::qword_ptr(x86::r8, SAFELIST_NEXT_OFFSET));
    builder.mov(x86::qword_ptr(x86::r10, SAFELIST_NEXT_OFFSET), x86::rcx);
    
    builder.mov(x86::rcx, x86::qword_ptr(x86::r8, SAFELIST_USED_OFFSET));
    builder.mov(x86::qword_ptr(x86::r10, SAFELIST_USED_OFFSET), x86::rcx);
    
    // Copy data using SIMD
    builder.mov(x86::r11, x86::qword_ptr(x86::r8, SAFELIST_NEXT_OFFSET));  // Number of elements to copy
    emitSIMDCopy(x86::r8, x86::r10, x86::r11);
    
    // Update the pointer at [addressReg + offsetReg]
    builder.mov(x86::ptr(x86::rdi, x86::rsi), x86::r10);
    
    // Save new list pointer before free call
    builder.push(x86::r10);
    
    // Free old memory
    builder.mov(x86::rdi, x86::r8);
    builder.mov(x86::rax, (uint64_t)free);
    builder.call(x86::rax);
    
    // Restore (not needed since we're returning, but good practice)
    builder.pop(x86::r10);
    
    // No function epilogue needed - no callee-saved registers used
    builder.ret();
}

void AsmLibrary::emitCompactListFunction() {
    builder.bind(compactListLabel);
    
    // No function prologue needed - using only caller-saved registers
    
    // Parameters: rdi = addressReg, rsi = offsetReg
    // rdi: addressReg (caller-saved)
    // rsi: offsetReg (caller-saved)
    
    // Load list pointer
    builder.mov(x86::r8, x86::ptr(x86::rdi, x86::rsi));  // r8 = list pointer
    
    // Spin lock
    emitSpinLock(x86::r8);
    
    // Compact algorithm: move all non-zero elements to front
    builder.mov(x86::r9, 0);   // r9 = write_index = 0
    builder.mov(x86::r10, 0);  // r10 = read_index = 0
    builder.mov(x86::r11, x86::qword_ptr(x86::r8, SAFELIST_NEXT_OFFSET));  // r11 = max_index
    
    Label compact_loop = builder.newLabel();
    Label compact_end = builder.newLabel();
    
    builder.bind(compact_loop);
    builder.cmp(x86::r10, x86::r11);
    builder.jge(compact_end);
    
    // Load data[read_index]
    builder.mov(x86::rax, x86::qword_ptr(x86::r8, x86::r10, 3, SAFELIST_DATA_OFFSET));
    
    // If non-zero, copy to write_index
    builder.test(x86::rax, x86::rax);
    Label skip_copy = builder.newLabel();
    builder.jz(skip_copy);
    
    builder.mov(x86::qword_ptr(x86::r8, x86::r9, 3, SAFELIST_DATA_OFFSET), x86::rax);
    builder.inc(x86::r9);
    
    builder.bind(skip_copy);
    builder.inc(x86::r10);
    builder.jmp(compact_loop);
    
    builder.bind(compact_end);
    
    // Update next_available
    builder.mov(x86::qword_ptr(x86::r8, SAFELIST_NEXT_OFFSET), x86::r9);
    
    // Check if we should shrink (used < 50% of capacity)
    builder.mov(x86::rax, x86::qword_ptr(x86::r8, SAFELIST_LENGTH_OFFSET));
    builder.shr(x86::rax, 1);  // capacity / 2
    builder.cmp(x86::r9, x86::rax);
    Label no_shrink = builder.newLabel();
    builder.jge(no_shrink);
    
    // Shrinking logic: calculate new size (at least current used + 25% growth room, minimum 4)
    builder.mov(x86::rax, x86::r9);   // current used slots
    builder.shr(x86::rax, 2);         // used / 4 (25% growth room)
    builder.add(x86::rax, x86::r9);   // used + growth room
    builder.mov(x86::rcx, 4);         // minimum size
    builder.cmp(x86::rax, x86::rcx);
    Label use_calculated = builder.newLabel();
    builder.jge(use_calculated);
    builder.mov(x86::rax, x86::rcx);  // Use minimum size
    
    builder.bind(use_calculated);
    builder.mov(x86::r10, x86::rax);  // r10 = new size (reusing r10 since loop is done)
    
    // Calculate new total size: 32 + (new_size * 8)
    builder.shl(x86::rax, 3);  // Multiply by 8
    builder.add(x86::rax, 32);
    
    // Save registers that calloc might clobber
    builder.push(x86::rdi);   // Save addressReg
    builder.push(x86::rsi);   // Save offsetReg
    builder.push(x86::r8);    // Save list pointer
    builder.push(x86::r9);    // Save compacted size
    builder.push(x86::r10);   // Save new size
    
    // Allocate new smaller memory
    builder.mov(x86::rdi, 1);
    builder.mov(x86::rsi, x86::rax);
    builder.mov(x86::rax, (uint64_t)calloc);
    builder.call(x86::rax);
    
    // Restore registers
    builder.pop(x86::r10);    // Restore new size
    builder.pop(x86::r9);     // Restore compacted size
    builder.pop(x86::r8);     // Restore list pointer
    builder.pop(x86::rsi);    // Restore offsetReg
    builder.pop(x86::rdi);    // Restore addressReg
    
    // New list pointer in rax
    builder.mov(x86::r11, x86::rax);  // r11 = new list pointer
    
    // Copy metadata to new buffer
    builder.mov(x86::qword_ptr(x86::r11, SAFELIST_LOCK_OFFSET), 0);   // Start unlocked
    builder.mov(x86::qword_ptr(x86::r11, SAFELIST_LENGTH_OFFSET), x86::r10);  // New capacity
    builder.mov(x86::qword_ptr(x86::r11, SAFELIST_NEXT_OFFSET), x86::r9);     // Compacted size
    builder.mov(x86::qword_ptr(x86::r11, SAFELIST_USED_OFFSET), x86::r9);     // Same as next_available after compact
    
    // Copy compacted data using SIMD (r9 elements from old to new)
    emitSIMDCopy(x86::r8, x86::r11, x86::r9);
    
    // Update the pointer at [addressReg + offsetReg] to point to new buffer
    builder.mov(x86::ptr(x86::rdi, x86::rsi), x86::r11);
    
    // Save registers for free call
    builder.push(x86::r11);   // Save new list pointer
    
    // Free old memory
    builder.mov(x86::rdi, x86::r8);
    builder.mov(x86::rax, (uint64_t)free);
    builder.call(x86::rax);
    
    // Restore new list pointer for unlock
    builder.pop(x86::r8);     // r8 = new list pointer for unlock
    
    builder.bind(no_shrink);
    
    // Unlock
    emitUnlock(x86::r8);
    
    // No function epilogue needed - no callee-saved registers used
    builder.ret();
}

void AsmLibrary::emitSpinLock(x86::Gp listPtrReg) {
    Label spin_loop = builder.newLabel();
    Label acquired = builder.newLabel();
    
    builder.bind(spin_loop);
    
    // Try to acquire lock using atomic compare-and-swap
    builder.mov(x86::rax, 0);  // Expected value (unlocked)
    builder.mov(x86::rdx, 1);  // Desired value (locked)
    builder.lock().cmpxchg(x86::qword_ptr(listPtrReg, SAFELIST_LOCK_OFFSET), x86::rdx);
    builder.jz(acquired);
    
    // Failed to acquire, pause and retry
    builder.pause();
    builder.jmp(spin_loop);
    
    builder.bind(acquired);
}

void AsmLibrary::emitUnlock(x86::Gp listPtrReg) {
    // Simply store 0 to unlock
    builder.mov(x86::qword_ptr(listPtrReg, SAFELIST_LOCK_OFFSET), 0);
}

void AsmLibrary::emitSIMDCopy(x86::Gp srcReg, x86::Gp dstReg, x86::Gp sizeReg) {
    // Copy data from src+32 to dst+32, sizeReg elements (8 bytes each)
    builder.mov(x86::rcx, sizeReg);  // Number of qwords to copy
    builder.test(x86::rcx, x86::rcx);
    
    Label copy_end = builder.newLabel();
    builder.jz(copy_end);
    
    builder.lea(x86::rsi, x86::ptr(srcReg, SAFELIST_DATA_OFFSET));  // Source
    builder.lea(x86::rdi, x86::ptr(dstReg, SAFELIST_DATA_OFFSET));  // Destination
    
    // Use rep movsq for efficient copying
    builder.rep().movsq();
    
    builder.bind(copy_end);
}

void AsmLibrary::emitAllFunctionDefinitions() {
    // Emit all actual functions that need labels and can be called
    emitResizeListFunction();
    emitCompactListFunction();
    emitAddToSafeListFunction();
    emitRemoveFromSafeListFunction();
}

void AsmLibrary::emitAddToSafeListFunction() {
    builder.bind(addToSafeListLabel);
    
    // Parameters: rdi = addressReg, rsi = offsetReg, rdx = valueReg
    // Load list pointer into r11
    builder.mov(x86::r11, x86::ptr(x86::rdi, x86::rsi));
    
    // Spin lock
    emitSpinLock(x86::r11);
    
    // Load next_available index
    builder.mov(x86::r10, x86::qword_ptr(x86::r11, SAFELIST_NEXT_OFFSET));
    
    // Load length for bounds check
    builder.mov(x86::r9, x86::qword_ptr(x86::r11, SAFELIST_LENGTH_OFFSET));
    
    // Check if we need to resize (next_available >= length)
    builder.cmp(x86::r10, x86::r9);
    Label no_resize = builder.newLabel();
    builder.jl(no_resize);
    
    // Need to resize - call resize function
    // Save value register before resize call
    builder.push(x86::rdx);
    builder.call(resizeListLabel);
    builder.pop(x86::rdx);
    
    // Reload list pointer after resize
    builder.mov(x86::r11, x86::ptr(x86::rdi, x86::rsi));
    builder.mov(x86::r10, x86::qword_ptr(x86::r11, SAFELIST_NEXT_OFFSET));
    
    builder.bind(no_resize);
    
    // Store value at data[next_available]
    builder.mov(x86::qword_ptr(x86::r11, x86::r10, 3, SAFELIST_DATA_OFFSET), x86::rdx);
    
    // Increment next_available
    builder.inc(x86::r10);
    builder.mov(x86::qword_ptr(x86::r11, SAFELIST_NEXT_OFFSET), x86::r10);
    
    // Increment used_slots
    builder.inc(x86::qword_ptr(x86::r11, SAFELIST_USED_OFFSET));
    
    // Unlock
    emitUnlock(x86::r11);
    
    builder.ret();
}

void AsmLibrary::emitRemoveFromSafeListFunction() {
    builder.bind(removeFromSafeListLabel);
    
    // Parameters: rdi = addressReg, rsi = offsetReg, rdx = indexReg
    // Load list pointer
    builder.mov(x86::r11, x86::ptr(x86::rdi, x86::rsi));
    
    // Spin lock
    emitSpinLock(x86::r11);
    
    // Bounds check
    builder.mov(x86::r10, x86::qword_ptr(x86::r11, SAFELIST_NEXT_OFFSET));
    builder.cmp(x86::rdx, x86::r10);
    Label bounds_ok = builder.newLabel();
    builder.jl(bounds_ok);
    
    // Index out of bounds - unlock and return
    emitUnlock(x86::r11);
    Label end = builder.newLabel();
    builder.jmp(end);
    
    builder.bind(bounds_ok);
    
    // Zero out the data at index
    builder.mov(x86::qword_ptr(x86::r11, x86::rdx, 3, SAFELIST_DATA_OFFSET), 0);
    
    // Decrement used_slots
    builder.dec(x86::qword_ptr(x86::r11, SAFELIST_USED_OFFSET));
    
    // Unlock
    emitUnlock(x86::r11);
    
    builder.bind(end);
    builder.ret();
}
