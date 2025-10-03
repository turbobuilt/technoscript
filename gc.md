# Garbage Collection

Garbage collection will run in a separate thread concurrently with a special optimization to prevent "resurrection". The goal is to avoid pauses completely.

The garbage collector scans all lexical scope objects currently active and traces through to all objects.

Then we have a list of all objects that have been allocated on each goroutine so we don't have to do locking. we will have to search through all of these to do the diff.

So we do a diff and find the ones that have not been reached.

On each one of these we set to 0 a "set flag", and then flush.  This will be set to one each time something is set to the address of this. In other words it tracks if a new reference to this is created.  This is because we are not pausing during mark sweep, so it's possible a race condition could have occured and mark sweep missed a reference to it.

To implement this, each time we have a set operation in regular code, the "set flag" on the referenced object will be set to one. But for memory saftey we will have a needs_set_flag that jumps if set to set the set_flag one and do a memory write fence. so really there should be two flags on the object one is if it needs set, the other is if set

Then we do mark/sweep again.

Theoretically if the set flag on an item and it's ancestors is still 0, we know that it is unreachable.

So we flush cache or whatever for the value and check the set flag on each of the ones originally not reached. If the set flag is 1, it's still live.
 - for these live ones we must additionally trace through all their descendants and remove them from suspicion of being "dead", as they also are still live.

After doing that and removing all live ones and their descendents from our checklist, we have a list of items that are truly dead.  We delete those and remove them from the list of allocated objects.

of note we would snapshot the list of addresses of all active objects before running the mark sweep.

for going thru the roots, for each goroutine, we would loop through the stack of roots.

For the second pass after setting the set_flage to 0, we will track all additions and removals so that we don't even try to mess with them. the reason is that new ones can't be a root for the tracked variables without hitting set_flags.

To track them, when pushing/popping from the active lexical scope stack, we would have a register set that is like "gc mode" to let us know if we are pushing and we will ignore items that were pushed there on section 2. popped values obviously shouldn't be traversed.

## mark sweep
each time a lexical scope goes active it's address must be pushed onto a goroutine local stack so we can know roots, and when it goes out of scope it must be popped from the stack. this is how we get the roots for mark sweep.