#pragma once
#include <atomic>
#include <memory>
#include <functional>
#include <chrono>

// Lock-free queue implementation using atomics
template<typename T>
class LockFreeQueue {
private:
    struct Node {
        std::atomic<T*> data{nullptr};
        std::atomic<Node*> next{nullptr};
    };
    
    std::atomic<Node*> head;
    std::atomic<Node*> tail;
    
public:
    LockFreeQueue() {
        Node* dummy = new Node;
        head.store(dummy);
        tail.store(dummy);
    }
    
    ~LockFreeQueue() {
        while (Node* oldHead = head.load()) {
            head.store(oldHead->next.load());
            delete oldHead;
        }
    }
    
    void enqueue(T* item) {
        Node* newNode = new Node;
        newNode->data.store(item);
        
        while (true) {
            Node* last = tail.load();
            Node* next = last->next.load();
            
            if (last == tail.load()) { // Still consistent?
                if (next == nullptr) {
                    // Try to link new node at end of list
                    if (last->next.compare_exchange_weak(next, newNode)) {
                        break; // Success
                    }
                } else {
                    // Try to swing tail to next node
                    tail.compare_exchange_weak(last, next);
                }
            }
        }
        
        // Try to swing tail to new node
        Node* expectedTail = tail.load();
        tail.compare_exchange_weak(expectedTail, newNode);
    }
    
    T* dequeue() {
        while (true) {
            Node* first = head.load();
            Node* last = tail.load();
            Node* next = first->next.load();
            
            if (first == head.load()) { // Still consistent?
                if (first == last) {
                    if (next == nullptr) {
                        return nullptr; // Empty queue
                    }
                    // Try to swing tail to next node
                    tail.compare_exchange_weak(last, next);
                } else {
                    // Read data before CAS, otherwise another dequeue might free the next node
                    T* data = next->data.load();
                    
                    // Try to swing head to next node
                    if (head.compare_exchange_weak(first, next)) {
                        delete first;
                        return data;
                    }
                }
            }
        }
    }
    
    bool empty() const {
        Node* first = head.load();
        Node* last = tail.load();
        return (first == last) && (first->next.load() == nullptr);
    }
};

// Timer task structure
struct TimerTask {
    std::chrono::steady_clock::time_point expireTime;
    std::function<void()> callback;
    
    TimerTask(std::chrono::steady_clock::time_point time, std::function<void()> cb)
        : expireTime(time), callback(std::move(cb)) {}
    
    // For priority queue (earliest expiration first) - note the > for min-heap
    bool operator>(const TimerTask& other) const {
        return expireTime > other.expireTime;
    }
};

// Expired timer callback (ready to execute immediately)
struct ExpiredTimer {
    std::function<void()> callback;
    
    ExpiredTimer(std::function<void()> cb) : callback(std::move(cb)) {}
};

// Worker thread states
#pragma once
#include <atomic>
#include <memory>

// Forward declarations
class Goroutine;

enum class WorkerState {
    IDLE,       // Worker is waiting for tasks
    RUNNING,    // Worker is executing a goroutine  
    SLEEPING,   // Worker is sleeping on condition variable
    STOPPING    // Worker is shutting down
};

// Worker thread information
struct WorkerThread {
    std::unique_ptr<std::thread> thread;
    std::atomic<WorkerState> state{WorkerState::IDLE};
    std::shared_ptr<Goroutine> assignedTask{nullptr};  // Task assigned by main thread
    uint32_t id;
    
    WorkerThread(uint32_t workerId) : id(workerId) {}
};