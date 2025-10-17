#pragma once

#include <./libtorch/include/ATen/ATen.h>
#include "ast.h"

// make tensor
at::Tensor makeTensor(DataType type) {
    return at::zeros({1}, at::dtype(at::kInt));
}