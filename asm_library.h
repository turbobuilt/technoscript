#pragma once

#include <asmjit/asmjit.h>
#include <memory>
#include <string>
#include <unordered_map>

using namespace asmjit;

/**
 * AsmLibrary - Fast memory-safe unordered list implementation
 * 
 * Features implemented:
 * - Atomic lock-based concurrent access
 * - Automatic resizing (4x growth) when capacity reached
 * - Compaction with automatic shrinking when usage < 50%
 * - SIMD-optimized memory copying for resize/compact operations
 * - Zero-cost removal (just zeros the slot)
 * - All operations emit efficient assembly code
 * 
 * Data structure layout:
 * - qword[0]: lock bit (0=unlocked, 1=locked)
 * - qword[1]: capacity (total slots available)
 * - qword[2]: next_available (index for next insertion)
 * - qword[3]: used_slots (count of non-zero slots)
 * - qword[4..n]: data array
 */

enum class AsmFunctionType {
    INLINE,      // Emit assembly inline
    DEFINITION,  // Emit function definition with label
    CALL         // Emit call to previously defined function
};

class AsmLibrary {
private:
    x86::Builder& builder;
    x86::Gp scopeReg;  // Usually r15 for current scope
    
    // Labels for utility functions
    Label resizeListLabel;
    Label compactListLabel;
    Label callocLabel;
    Label addToSafeListLabel;
    Label removeFromSafeListLabel;
    
    // External function addresses
    std::unordered_map<std::string, void*> externalFunctions;
    
public:
    AsmLibrary(x86::Builder& builder_ref, x86::Gp scope_reg);
    
    // Initialize external function addresses
    void initializeExternalFunctions();
    
    // Safe unordered list operations
    void makeSafeUnorderedList(x86::Gp addressReg, x86::Gp offsetReg, int32_t initialSize = 16);
    void addToSafeList(x86::Gp addressReg, x86::Gp offsetReg, x86::Gp valueReg, AsmFunctionType type = AsmFunctionType::INLINE);
    void removeFromSafeList(x86::Gp addressReg, x86::Gp offsetReg, x86::Gp indexReg, AsmFunctionType type = AsmFunctionType::INLINE);
    void compactSafeList(x86::Gp addressReg, x86::Gp offsetReg, AsmFunctionType type = AsmFunctionType::CALL);
    
    // Utility function definitions (emit once)
    void emitResizeListFunction();
    void emitCompactListFunction();
    void emitAddToSafeListFunction();
    void emitRemoveFromSafeListFunction();
    
    // Emit all actual function definitions that need labels
    void emitAllFunctionDefinitions();
    
    // Helper methods
    void emitSpinLock(x86::Gp listPtrReg);
    void emitUnlock(x86::Gp listPtrReg);
    void emitSIMDCopy(x86::Gp srcReg, x86::Gp dstReg, x86::Gp sizeReg);
    
    // Get labels for external use
    Label getResizeListLabel() const { return resizeListLabel; }
    Label getCompactListLabel() const { return compactListLabel; }
    Label getAddToSafeListLabel() const { return addToSafeListLabel; }
    Label getRemoveFromSafeListLabel() const { return removeFromSafeListLabel; }
};

// Safe unordered list structure layout:
// Offset 0:  qword lock (bit 0 = locked, rest unused)
// Offset 8:  qword length (total capacity)
// Offset 16: qword next_available (index of next free slot)
// Offset 24: qword used_slots (number of used slots)
// Offset 32: data array (qword * length)

constexpr int32_t SAFELIST_LOCK_OFFSET = 0;
constexpr int32_t SAFELIST_LENGTH_OFFSET = 8;
constexpr int32_t SAFELIST_NEXT_OFFSET = 16;
constexpr int32_t SAFELIST_USED_OFFSET = 24;
constexpr int32_t SAFELIST_DATA_OFFSET = 32;
