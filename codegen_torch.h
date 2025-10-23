#pragma once

#pragma once

#ifdef USE_LIBTORCH
#include <ATen/ATen.h>
#endif

#include "ast.h"

// make tensor
#ifdef USE_LIBTORCH
at::Tensor makeTensor(DataType type) {
    return at::zeros({1}, at::dtype(at::kInt));
}
#else
// Placeholder for when libtorch is not available
void* makeTensor(DataType type) {
    return nullptr;
}
#endif