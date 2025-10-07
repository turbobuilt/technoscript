Concurrent GC

- Mark/Sweep each goroutine
    - unmarked objects are deletion candidates
- for unmarked objects, set needs_set_flag=1 on them
    - for all sets, the code has been emitted such that if needs_set_flag=1, it will set set_flag=1 each time a variable is set to reference the object
    - this ensures that from this point on, if any of these deletion candidates are ever reassigned, we will know
    - there is no need to freeze or lock the stack frames here
- we do another mark sweep
    - if it is still not found, AND the set flag isn't flipped it is guaranteed that it is deleteable as long as none of it's parents had set_flag=1 set
        - this is a key point to the theorem. as long as the second mark sweep takes place any time after the needs_set_flag=1 is set, if neither it nor it's ancestors had set_flag=1 set by the time the second sweep completes, it is provably not live
        - another key point here is that 
