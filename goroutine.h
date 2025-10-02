#pragma once
#include <queue>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <functional>
#include <atomic>
#include <memory>
#include <csetjmp>
#include <map>
#include <array>
#include <iostream>
#include <cstdlib>
#include "lockfree_queue.h"

// Forward declarations
class Goroutine;
class EventLoop;

// Promise system for async/await
struct Promise {
    enum class State { PENDING, RESOLVED, REJECTED };
    
    uint64_t id;
    State state;
    int64_t resolvedValue;  // For sleep, this will be the actual elapsed time
    std::shared_ptr<Goroutine> waitingGoroutine;
    
    Promise(uint64_t promiseId) : id(promiseId), state(State::PENDING), resolvedValue(0) {}
};

// Goroutine states
enum class GoroutineState {
    READY,      // Ready to run
    RUNNING,    // Currently running
    WAITING,    // Waiting for something (timer, I/O, etc.)
    AWAITING_PROMISE, // Suspended waiting for promise resolution
    DEAD        // Finished execution
};

// Goroutine context - saves register state
struct GoroutineContext {
    jmp_buf registers;
    void* stackPointer;
    size_t stackSize;
    std::unique_ptr<uint8_t[]> stack;
    
    GoroutineContext(size_t stackSz = 64 * 1024) : stackSize(stackSz) {
        stack = std::make_unique<uint8_t[]>(stackSize);
        stackPointer = stack.get() + stackSize; // Stack grows downward
    }
};

// Individual goroutine
class Goroutine : public std::enable_shared_from_this<Goroutine> {
public:
    static uint64_t nextId;
    uint64_t id;
    GoroutineState state;
    std::unique_ptr<GoroutineContext> context;
    std::function<void()> entryPoint;
    
    // Promise support
    uint64_t awaitingPromiseId = 0;  // 0 means not awaiting any promise
    int64_t promiseResolvedValue = 0; // Value from resolved promise
    
    Goroutine(std::function<void()> entry) 
        : id(++nextId), state(GoroutineState::READY), entryPoint(std::move(entry)) {
        context = std::make_unique<GoroutineContext>();
    }
    
    void run();
    void suspend(uint64_t promiseId);
    void resume(int64_t resolvedValue);
    bool isFinished() const { return state == GoroutineState::DEAD; }
};

// Main event loop managing all goroutines
class EventLoop {
private:
    // Lock-free queues for high performance
    LockFreeQueue<std::shared_ptr<Goroutine>> taskQueue;
    LockFreeQueue<ExpiredTimer> expiredTimerQueue;  // Higher priority than regular tasks
    
    // Timer management - priority queue for unexpired timers (earliest first)
    std::priority_queue<TimerTask, std::vector<TimerTask>, std::greater<TimerTask>> unexpiredTimers;
    std::mutex timerMutex;  // Only for unexpired timers priority queue
    
    // Promise system - unified with task system for better performance
    std::map<uint64_t, Promise> promises;
    std::mutex promisesMutex;  // Separate lock for promise operations
    static uint64_t nextPromiseId;
    
    // Thread pool management
    std::vector<std::unique_ptr<WorkerThread>> workerThreads;
    size_t maxWorkers;
    std::atomic<size_t> activeWorkers{0};     // Number of workers currently created
    std::atomic<size_t> sleepingWorkers{0};   // Number of workers sleeping on CV
    
    // Synchronization for sleeping workers
    std::mutex sleepMutex;
    std::condition_variable workerWakeup;     // Wake up sleeping workers
    std::condition_variable mainLoopWakeup;   // Wake up main loop when workers sleep
    std::atomic<bool> running{true};
    
    // Internal methods for performance optimization
    void moveExpiredTimersToQueue();  // Move expired timers from priority queue to expired queue
    std::shared_ptr<Goroutine> checkExpiredTimers();  // Get next expired timer as goroutine
    void workerThreadFunction(uint32_t workerId);
    void createWorkerIfNeeded();
    void wakeupSleepingWorkers(size_t count = 1);
    bool assignTaskToSleepingWorker(std::shared_ptr<Goroutine> task);  // Assign task to sleeping worker
    
public:
    EventLoop();
    ~EventLoop();
    
    // Core goroutine operations (lock-free for performance)
    void spawnGoroutine(std::function<void()> entryPoint);
    
    // Timer operations (thread-safe)
    void addTimer(std::chrono::milliseconds delay, std::function<void()> callback);
    
    // Promise system for async/await
    uint64_t createPromise();
    void resolvePromise(uint64_t promiseId, int64_t value);
    int64_t awaitPromise(uint64_t promiseId, std::shared_ptr<Goroutine> currentGoroutine);
    
    // Event loop control
    void run();
    void shutdown();
    
    // Worker monitoring
    size_t getActiveWorkers() const { return activeWorkers.load(); }
    size_t getSleepingWorkers() const { return sleepingWorkers.load(); }
    bool isEmpty() const { 
        // Best-effort check without taking locks for performance
        if (!taskQueue.empty() || !expiredTimerQueue.empty()) {
            return false;
        }
        // Only check unexpired timers if other queues are empty (minimize lock contention)
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(timerMutex));
        return unexpiredTimers.empty();
    }
    
    // Singleton access
    static EventLoop& getInstance();
    
    // Allow Goroutine to access queues for efficient resume
    friend class Goroutine;
};

// Runtime functions callable from generated code
extern "C" {
    // Called by 'go' statements to spawn new goroutines
    void runtime_spawn_goroutine(void (*func)(void*), void* args, size_t argsSize);
    
    // Called by 'setTimeout' statements to schedule delayed function execution
    void runtime_set_timeout(void (*func)(void*), void* args, size_t argsSize, int delayMs);
    
    // Promise and async/await support
    uint64_t runtime_sleep(int64_t milliseconds);  // Returns promise ID
    int64_t runtime_await_promise(uint64_t promiseId); // Suspends current goroutine, returns resolved value
    
    // Start the event loop (called at end of main)
    void runtime_start_event_loop();
    
    // Shutdown the runtime
    void runtime_shutdown();
}