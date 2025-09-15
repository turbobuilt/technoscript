var global_var: int64 = 100;

function outer(param_x) {
    var outer_var: int64 = 200;
    
    print(outer_var)  // Should be 200
    
    function inner(param_y) {
        print(param_y)
    }
    
    print(outer_var)  // Should still be 200
    inner(outer_var)  // Pass outer_var to inner
}

outer(global_var)
