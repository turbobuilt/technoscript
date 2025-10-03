# Garbage Collection Implementation

This implementation provides a concurrent garbage collector based on the design in `gc.md`.

## Key Features

### 1. **Concurrent Mark-Sweep with Resurrection Prevention**
- Runs in a separate thread without pausing program execution
- Uses a sophisticated "set flag" mechanism to detect objects that gain new references during GC

### 2. **Per-Goroutine Object Tracking**
- Each goroutine maintains its own list of allocated objects (lock-free during normal execution)
- Scope stack tracks active lexical scopes as GC roots

### 3. **Four-Phase Collection Algorithm**

#### Phase 1: Initial Mark-Sweep
- Snapshot all allocated objects from all goroutines
- Collect roots from goroutine scope stacks
- Mark reachable objects
- Identify suspected dead objects

#### Phase 2: Set Flag Monitoring
- Set `needs_set_flag` on suspected dead objects
- Clear `set_flag` on these objects
- Enter GC mode (scope push/pop ignored for tracked objects)
- Wait briefly for program to execute

#### Phase 3: Second Mark-Sweep
- Check `set_flag` on suspected objects
- Objects with `set_flag=1` were "resurrected" (gained new references)
- Mark resurrected objects and descendants as live
- Remaining objects are truly dead

#### Phase 4: Cleanup
- Free truly dead objects
- Remove from goroutine allocation lists

## Code Integration

### Object Allocation (`generateNewExpr` in codegen.cpp)
```cpp
// After allocating object with calloc:
gc_track_object(obj);  // Add to current goroutine's allocation list
```

### Scope Management
```cpp
// On scope entry:
gc_push_scope(scope);  // Add to GC roots

// On scope exit:
gc_pop_scope();  // Remove from GC roots
```

### Assignment Tracking
```cpp
// When assigning object references:
gc_handle_assignment(targetObj);  // Sets set_flag if object is under GC suspicion
```

## Object Header Layout

Offset 0-7: Flags (64-bit)
- Bit 0: `needs_set_flag` - Object is suspected dead
- Bit 1: `set_flag` - New reference created during GC
- Bit 2: `gc_marked` - Marked as reachable

Offset 8-15: Class reference pointer
Offset 16-23: Dynamic variables pointer (unused)
Offset 24+: Object fields

## Scope Header Layout

Offset 0-7: Flags (64-bit)
- Bit 0: `gc_marked` - Marked as reachable

Offset 8+: Variables/parameters

## Current Limitations

1. **Single Goroutine Support**: Currently only tracks objects from the active goroutine. Full implementation needs to iterate all goroutines safely.

2. **Scope Tracing**: Scope objects need metadata about their layout to properly trace variable references. Currently simplified.

3. **GC Trigger**: Runs periodically (every 100ms). Could be enhanced with heap pressure-based triggering.

4. **Object Graph**: Only traces object-to-object references through class fields. Closures and other reference types need additional support.

## Future Enhancements

1. Add goroutine registry to track all active goroutines
2. Implement scope metadata for proper variable tracing
3. Add write barriers for generational GC
4. Implement heap pressure monitoring for adaptive GC timing
5. Add GC statistics and profiling
