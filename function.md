Ok so now comes the code generation part. We want everything emitted as raw assembly, no runtime at all!

Of particular note are functions. In a javascripty language, all functions should really be treated as closures. We will use the same setup code to setup the global scope as a function for simplicity, passing in a boolean "root" to determine if root or not for code reuse.

The first thing that will take place is we will save the value of R15 on the stack. Then we will allocate on the HEAP the space required to fit the lexical scope for this function. The size for this will be the totalSize on the LexicalScopeNode. We will then assign to R15 the current address of the current lexical scope.

The next step is to create the closures, as they have been "hoisted". So we have the variables map on the lexical scope node, and we go through them to find the Closure variables, and on variableInfo we have their offset.

So at r15+offset, is where the closure goes.

That closure is supposed to contain first the address of the function and then addresses to any needed lexical scopes. Since we may not know the address of the function while compiling, we have a global data structure that is like an array where we push the offset and the FunctionDeclNode* pointer. Later we will go through and put the addresses once we know them.

Then in the code, we will access all variables in the current scope as r15+offset.

When a function is called, we do proper convention to pass any arguments, and then after that, the lexical scope addresses needed will be later arguments.

Therefore when accessing members of the parent lexical scope the code would be almost identical to accessing members of Objects passed as arguments.  If there were few arguments, and they stayed in registers, it would be pretty fast access. Otherwise we would have to load the address from the stack to rax and then access the property.

So really the way a function would be called is that when you get to the place to call it, it's actually a variable either in the current scope or a parent scope. So the first step would be to get the address of the closure in rax or something like that.

If it was defined in current scope it would be r15+offset (in lexicalscopenode variableinfo).

If it was defined in an ancestor scope you would get the ancestor scope heap start address from the appropriate register for the argument or on stack if lots of arguments and it was there, then you would get the address of the closure based on the offset from there.  That offset woud have to be put in at compile time based on the fact that VariableInfo has an offset property.





In the corresponding epilogue we will restore the current value of r15.



Therefore we will have "hoisting" where the closure is created at the beginning of the function scope in which the function is defined.

So the first thing that will take place in any function scope is assignment of address and lexicalscope to closures. In this code base, we are not going to allow redefining functions at least for now.

So when you enter the code and let's take this simple code

var x: int64 = 1
function y(){
    console.log(x)
}

The first thing that will happen is that a variable called y will be initialized with the address of y and the lexical scope address that contains x
