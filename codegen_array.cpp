#include "codegen_array.h"

// Instantiate the int64_t variant once in this TU
template std::vector<int64_t>* makeArray<int64_t>();

extern "C" {
    std::vector<int64_t>* makeArrayInt64() {
        return new std::vector<int64_t>({1, 2, 3, 4, 5});
    }

    void printArrayInt64(std::vector<int64_t>* arr) {
        printArray<int64_t>(arr);
    }
}