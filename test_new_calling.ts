// Test the new calling convention where scope is allocated at call site

function add(a, b) {
    return a + b;
}

function main() {
    var x = 5;
    var y = 10;
    var result = add(x, y);
    print(result);  // Should print 15
}
