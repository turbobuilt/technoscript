var global_var: int64 = 100;

function outer(param_x) {
    var outer_var: int64 = 200;
    print(outer_var)  // Test if outer_var is 200 right after initialization
}

outer(global_var)
