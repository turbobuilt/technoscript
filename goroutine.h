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

// Forward declaration
class Goroutine;
class EventLoop;

// Goroutine states
enum class GoroutineState {
    READY,      // Ready to run
    RUNNING,    // Currently running
    WAITING,    // Waiting for something (timer, I/O, etc.)
    DEAD        // Finished execution
};

// Timer task for the event loop
struct TimerTask {
    std::chrono::steady_clock::time_point expireTime;
    std::function<void()> callback;
    
    // For priority queue (earliest expiration first)
    bool operator>(const TimerTask& other) const {
        return expireTime > other.expireTime;
    }
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
class Goroutine {
public:
    static uint64_t nextId;
    uint64_t id;
    GoroutineState state;
    std::unique_ptr<GoroutineContext> context;
    std::function<void()> entryPoint;
    
    Goroutine(std::function<void()> entry) 
        : id(++nextId), state(GoroutineState::READY), entryPoint(std::move(entry)) {
        context = std::make_unique<GoroutineContext>();
    }
    
    void run();
    bool isFinished() const { return state == GoroutineState::DEAD; }
};

// Main event loop managing all goroutines
class EventLoop {
private:
    // Queues and data structures
    std::queue<std::shared_ptr<Goroutine>> pendingTasks;
    std::priority_queue<TimerTask, std::vector<TimerTask>, std::greater<TimerTask>> unexpiredTimers;
    
    // Thread management
    std::vector<std::thread> workerThreads;
    size_t maxThreads;
    std::atomic<size_t> freeThreads;  // Track number of free threads
    
    // Synchronization
    std::mutex queueMutex;
    std::condition_variable workAvailable;
    std::atomic<bool> running{true};
    
    // Main goroutine (created by main function)
    std::shared_ptr<Goroutine> mainGoroutine;
    
    void processExpiredTimers();
    void runTask(std::shared_ptr<Goroutine> task);
    
public:
    EventLoop();
    ~EventLoop();
    
    // Add a new goroutine to the pending queue
    void spawnGoroutine(std::function<void()> entryPoint);
    
    // Add a timer task
    void addTimer(std::chrono::milliseconds delay, std::function<void()> callback);
    
    // Start the event loop (blocks until all goroutines complete)
    void run();
    
    // Signal shutdown
    void shutdown();
    
    // Get singleton instance
    static EventLoop& getInstance();
};

// Runtime functions callable from generated code
extern "C" {
    // Called by 'go' statements to spawn new goroutines
    void runtime_spawn_goroutine(void (*func)(void*), void* args, size_t argsSize);
    
    // Start the event loop (called at end of main)
    void runtime_start_event_loop();
    
    // Shutdown the runtime
    void runtime_shutdown();
}