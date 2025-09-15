var global_var: int64 = 100;

function outer(param_x) {
    function inner() {
        print(global_var)
    }
    
    inner()
}

outer(global_var)
