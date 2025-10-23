#include "safe_unordered_list.h"

#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <new>

static constexpr uint64_t kHeaderSize = sizeof(SafeUnorderedListHeader);
static constexpr uint64_t kPointerSize = sizeof(void*);
static constexpr uint64_t kInitialCapacity = 8;

SafeUnorderedList::SafeUnorderedList() : list(nullptr) {
    const size_t bytes = kHeaderSize + kInitialCapacity * kPointerSize;
    list = static_cast<SafeUnorderedListHeader*>(std::malloc(bytes));
    if (!list) {
        throw std::bad_alloc();
    }
    list->lock = 0;
    list->length = kInitialCapacity;
    list->next_available = 0;
    list->used_slots = 0;
}

SafeUnorderedList::~SafeUnorderedList() {
    std::free(list);
    list = nullptr;
}

void SafeUnorderedList::add(void* value) {
    if (!value) {
        return;
    }

    auto* lock = reinterpret_cast<std::atomic<uint64_t>*>(&list->lock);
    uint64_t expected = 0;
    while (!lock->compare_exchange_weak(expected, 1, std::memory_order_acquire)) {
        expected = 0;
    }

    uint64_t position = list->next_available;
    uint64_t capacity = list->length;

    if (position >= capacity) {
        uint64_t newCapacity = capacity * 2;
        const size_t newBytes = kHeaderSize + newCapacity * kPointerSize;
        auto* newList = static_cast<SafeUnorderedListHeader*>(std::realloc(list, newBytes));
        if (!newList) {
            lock->store(0, std::memory_order_release);
            throw std::bad_alloc();
        }
        std::memset(reinterpret_cast<uint8_t*>(newList) + kHeaderSize + capacity * kPointerSize,
                        0,
                        (newCapacity - capacity) * kPointerSize);
        list = newList;
        list->length = newCapacity;
        lock = reinterpret_cast<std::atomic<uint64_t>*>(&list->lock);
    }

    auto* data = reinterpret_cast<void**>(reinterpret_cast<uint8_t*>(list) + kHeaderSize);
    data[position] = value;
    list->next_available = position + 1;
    list->used_slots = list->next_available;

    lock->store(0, std::memory_order_release);
}

void SafeUnorderedList::remove(void* obj) {
    if (!obj) {
        return;
    }

    auto* lock = reinterpret_cast<std::atomic<uint64_t>*>(&list->lock);
    uint64_t expected = 0;
    while (!lock->compare_exchange_weak(expected, 1, std::memory_order_acquire)) {
        expected = 0;
    }

    uint64_t count = list->next_available;
    auto* data = reinterpret_cast<void**>(reinterpret_cast<uint8_t*>(list) + kHeaderSize);
    bool found = false;

    for (uint64_t i = 0; i < count; ++i) {
        if (data[i] == obj) {
            uint64_t lastIndex = count - 1;
            data[i] = data[lastIndex];
            data[lastIndex] = nullptr;
            list->next_available = lastIndex;
            list->used_slots = lastIndex;
            found = true;
            break;
        }
    }

    if (!found) {
        lock->store(0, std::memory_order_release);
        return;
    }

    uint64_t capacity = list->length;
    if (capacity > 16 && list->next_available < (capacity >> 1)) {
        uint64_t newCapacity = capacity >> 1;
        const size_t newBytes = kHeaderSize + newCapacity * kPointerSize;
        auto* newList = static_cast<SafeUnorderedListHeader*>(std::realloc(list, newBytes));
        if (newList) {
            list = newList;
            list->length = newCapacity;
            lock = reinterpret_cast<std::atomic<uint64_t>*>(&list->lock);
        }
    }

    lock->store(0, std::memory_order_release);
}

void SafeUnorderedList::snapshot(std::vector<void*>& out) {
    auto* lock = reinterpret_cast<std::atomic<uint64_t>*>(&list->lock);
    uint64_t expected = 0;
    while (!lock->compare_exchange_weak(expected, 1, std::memory_order_acquire)) {
        expected = 0;
    }

    uint64_t count = list->next_available;
    auto* data = reinterpret_cast<void**>(reinterpret_cast<uint8_t*>(list) + kHeaderSize);
    out.clear();
    out.reserve(count);
    for (uint64_t i = 0; i < count; ++i) {
        if (data[i]) {
            out.push_back(data[i]);
        }
    }

    lock->store(0, std::memory_order_release);
}

void SafeUnorderedList::garbageCollect() {
    auto* lock = reinterpret_cast<std::atomic<uint64_t>*>(&list->lock);
    uint64_t expected = 0;
    while (!lock->compare_exchange_weak(expected, 1, std::memory_order_acquire)) {
        expected = 0;
    }

    uint64_t count = list->next_available;
    auto* data = reinterpret_cast<void**>(reinterpret_cast<uint8_t*>(list) + kHeaderSize);
    uint64_t write = 0;
    for (uint64_t read = 0; read < count; ++read) {
        void* value = data[read];
        if (value) {
            if (write != read) {
                data[write] = value;
                data[read] = nullptr;
            }
            ++write;
        }
    }
    for (uint64_t i = write; i < count; ++i) {
        data[i] = nullptr;
    }
    list->next_available = write;
    list->used_slots = write;

    uint64_t capacity = list->length;
    if (capacity > 16 && write < (capacity >> 1)) {
        uint64_t newCapacity = capacity >> 1;
        const size_t newBytes = kHeaderSize + newCapacity * kPointerSize;
        auto* newList = static_cast<SafeUnorderedListHeader*>(std::realloc(list, newBytes));
        if (newList) {
            list = newList;
            list->length = newCapacity;
            lock = reinterpret_cast<std::atomic<uint64_t>*>(&list->lock);
        }
    }

    lock->store(0, std::memory_order_release);
}
