function test() {
    print "Hello from goroutine";
}

function main() {
    go test();
    print "Main function";
}