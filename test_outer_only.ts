var global_var: int64 = 100;

function outer(param_x) {
    var outer_var: int64 = 200;
    
    print(param_x)
    print(outer_var)
    print(global_var)
}

outer(global_var)
