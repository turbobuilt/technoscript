#include "codegen_array.h"
#include <vector>
#include <cstdint>
#include <iostream>


extern "C" {
    std::vector<int64_t>* makeArrayInt64() {
        return new std::vector<int64_t>({1,2,3,4,5});
    }
    // print array
    void printArrayInt64(std::vector<int64_t>* arr) {
        printArray(arr);
    }
}

template <typename T>
void printArray(std::vector<T>* arr) {
    if (!arr) {
        std::cout << "Array is null" << std::endl;
        return;
    }
    std::cout << "Array contents: [";
    for (size_t i = 0; i < arr->size() && i < 10; i++) {
        std::cout << (*arr)[i];
        if (i < arr->size() - 1) std::cout << ", ";
    }
    std::cout << "]" << std::endl;
}