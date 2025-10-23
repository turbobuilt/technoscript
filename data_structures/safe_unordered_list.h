#pragma once

#include <atomic>
#include <cstdint>
#include <vector>

struct SafeUnorderedListHeader {
    uint64_t lock;
    uint64_t length;
    uint64_t next_available;
    uint64_t used_slots;
};

class SafeUnorderedList {
public:
    SafeUnorderedList();
    ~SafeUnorderedList();

    void add(void* obj);
    void remove(void* obj);
    void snapshot(std::vector<void*>& out);
    void garbageCollect();

private:
    SafeUnorderedListHeader* list;

    SafeUnorderedList(const SafeUnorderedList&) = delete;
    SafeUnorderedList& operator=(const SafeUnorderedList&) = delete;
};
