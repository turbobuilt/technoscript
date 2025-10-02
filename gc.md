# Garbage Collection

Garbage collection will run in a separate thread concurrently with a special optimization to prevent "resurrection". The goal is to avoid pauses completely.

The garbage collector scans all lexical scope objects currently active and traces through to all objects.

Then we have a list of all objects that have been allocated.

So we do a diff and find the ones that have not been reached.

On each one of these we set to 0 a "set flag", and then flush.  This will be set to one each time something is set to the address of this. In other words it tracks if a new reference to this is created.  This is because we are not pausing during mark sweep, so it's possible a race condition could have occured and mark sweep missed a reference to it.

To implement this, each time we have a set operation, the "set flag" on the referenced object will be set to one. it's just one extra instruction.

Then we do mark/sweep again.

Theoretically if the set flag on an item and it's ancestors is still 0, we know that it is unreachable.

So we flush cache or whatever for the value and check the set flag on each of the ones originally not reached. If the set flag is 1, it's still live.
 - for these live ones we must additionally trace through all their descendants and remove them from suspicion of being "dead", as they also are still live.

After doing that and removing all live ones and their descendents from our checklist, we have a list of items that are truly dead.  We delete those and remove them from the list of allocated objects.

of note we would snapshot the list of addresses before running the mark sweep

## mark sweep
each time a lexical scope goes active it's address must be pushed onto a goroutine local stack so we can know roots, and when it goes out of scope it must be popped from the stack. this is how we get the roots for mark sweep.