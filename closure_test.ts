func main() {
    var x: int64 = 42;
    
    func inner() {
        var y: int32 = x;  // Captures x from parent scope
        print y;
    }
    
    inner();
}
