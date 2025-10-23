#include <cassert>
#include <vector>
#include <iostream>
#include "data_structures/safe_unordered_list.h"

int main() {
    SafeUnorderedList list;

    int a = 1, b = 2, c = 3, d = 4;

    // Add elements
    list.add(&a);
    list.add(&b);
    list.add(&c);

    // Snapshot should contain 3 items
    std::vector<void*> snap;
    list.snapshot(snap);
    assert(snap.size() == 3);

    // Remove middle element and verify compaction (unordered)
    list.remove(&b);
    snap.clear();
    list.snapshot(snap);
    assert(snap.size() == 2);
    // Remaining should be a and c in some order
    bool has_a = false, has_c = false;
    for (void* p : snap) {
        has_a |= (p == &a);
        has_c |= (p == &c);
    }
    assert(has_a && has_c);

    // Add another element; capacity growth is internal, just verify presence
    list.add(&d);
    snap.clear();
    list.snapshot(snap);
    assert(snap.size() == 3);
    bool has_d = false;
    for (void* p : snap) has_d |= (p == &d);
    assert(has_d);

    // Remove all and ensure empty
    list.remove(&a);
    list.remove(&c);
    list.remove(&d);
    snap.clear();
    list.snapshot(snap);
    assert(snap.size() == 0);

    // Garbage collect on empty should be safe
    list.garbageCollect();

    std::cout << "safe_unordered_list basic test passed\n";
    return 0;
}

