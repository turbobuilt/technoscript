# unique ref tracking [not currently used - we will use gc.md]

Instead of traditional reference counting, this language does an experimental memory technique called reference tracking.

Each object will keep track of the addresses of all objects that reference it, instead of just counting.

When created, in the header, the object will have 8*8byte preallocated in the object which allows tracking up to two addresses, and then additional space can be allocated and placed in a pointer which is always in the space after that. this can be set to heap object location for additional space.

When an item references another item, an object field, for example, it will have 2*8byte. the first is the address of the actual object, the second is the index of the reference record in the target object.

# Current Gen

For this prototype we will have 8*8byte spaces allocated for referencing addresses and 1*8byte that is a pointer to allow malloc for additional space if needed (won't use for now, but important so we don't have to change layout later).

For now, when adding a reference we will lock, loop through to find first zero value position and write the address there and unlock.  We will then take whatever index that is and return it so that it can be stored with the referencing object for O(1) removal time. In this first instance, we will however loop through all to find a free space, and throw if there isn't one.

All object references will be 2*8byte instead of just 8 byte. The first 8 bytes will be the address and the second will be the offset in the referencing object.  That way when we unset the object we know the exact offset to zero out in the referenced object.

When removing we atomic set to zero and put in the set to test for gc

# Next Gen [we will do this later]

The references list is pretty complicated, as references can be added and removed at will at arbitrary locations so it's not as simple as you would think.  To solve this we have three separate memory things.

The first stores the actual references. It is of size n*8.  The next two are size n*2+8, where the second stores a list of free space indexes as 16 bit ints, and the third stores a list of used space indexes as 16 bit ints. (if an object has more than 4096 references it crashes with an exception, so 16 bit should work fine).

The two that store the lists are as follows. The first item is a 64 bit field that stores the size of the list*2. The reason is when we start modifying we atomically increment it by 1 to lock it while we update, and then atomically increment again by 1 when done. So the real size of the list would be that number divided by 2.

When looking for a free spot we follow this algorithm.

read value of current free space offset variable
if odd, it's busy, loop and try again.
if even, compare exchange with that value-1
if failed, it's busy, loop and try again.
now that we have that value divide it by 2 to get the index of the next free space offset.
get the value at the start of this mini 2*n free_section + offset, which will contain a free_index.
write the address of the referencing object at list_address + 8*free_index
decrement free space offset.

When an object it releasing another object we follow a similar algorithm. however, instead of reading the value and decrementing, we store the free_index and increment.

# "Garbage Collection"

Each time a reference is decremented, we do a lock and count the number of remaining references. if it's zero, we destroy it. We also fire off something to the gc lock and adding it to a list of destroyed objects. Then we loop through the objects in the gc queue and set to zero any references of this object. When objects are destroyed, there should be a single destroy function all reference and the destroy function locks and checks destroyed objects first. to prevent double deletion. Once it loops through and removes it from the queue if it's there as well, remove it from the destroyed objects thing.

Othewise, we put the address of the object in a queue that is handled by a background thread

In a separate garbage collection process we loop through the items in the queue. For each one, we look at the items that reference it and trace down through all the items they reference, and all the items that reference them, etc, all the way down to "in scope" variables. We have a data structure that sets a flag for each object address to detect if already visited to prevent cycle issues.  If it is found that the chains never end at a scope variable, memory is freed. we then go through the other items in the queue to see if it shows up there again and zero out.

# Roots

We must detect if objects are in scope.  This language treats lexical scopes as objects.  Therefore each object should have a property in it that is a reference to the lexical scope it is in. If this is non zero, we know it is attached to a lexical scope.

Each lexical scope should have another property that is "in scope" and when it's code is done, it is set to false.

Each lexical scope will have to be treated like an object as well in the sense that it will have to keep track of things that reference it.

When things get too many references > 256 it's a problem. So we stop doing this method, and quit saving references to it.

To gc for that, we have another method.

Each time we allocate an object, we write to a linked list containing the objects address, and a pointer to a "type" structure that knows how to interpret the object's memory region. then we loop through the linked list periodically, and for each item, we use the type structure to know which items in it are pointers. We then lookg to see if any of the objects reference the item. if the number of references to the item drops below 256 we flip the switch and start regular tracking memory references