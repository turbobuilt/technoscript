#pragma once

#include <vector>
#include <cstdint>
#include <iostream>


// Template function declarations
template <typename T>
std::vector<T>* makeArray() {
    return new std::vector<T>({1,2,3,4,5});
}

// Explicit instantiation provided in .cpp so each TU can reuse it without ODR violations
extern template std::vector<int64_t>* makeArray<int64_t>();

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

extern "C" {
    std::vector<int64_t>* makeArrayInt64();
    void printArrayInt64(std::vector<int64_t>* arr);
}
