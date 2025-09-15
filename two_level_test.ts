var global_var: int64 = 100;

function outer(param_x) {
    var outer_var: int64 = 200;
    
    function inner(param_y) {
        print(param_y)
        print(param_x)
        print(outer_var)
        print(global_var)
    }
    
    inner(outer_var)
    print(param_x)
}

outer(global_var)
