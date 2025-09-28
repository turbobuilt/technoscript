#include "goroutine.h"
#include <iostream>
#include <algorithm>
#include <cstring>

// Static member initialization
uint64_t Goroutine::nextId = 0;

// Goroutine implementation
void Goroutine::run() {
    if (state != GoroutineState::READY) {
        return;
    }
    
    state = GoroutineState::RUNNING;
    
    try {
        // Set up stack context and run the goroutine
        if (setjmp(context->registers) == 0) {
            // First time - set up stack and call entry point
            entryPoint();
        }
        // If we return here, the goroutine finished
        state = GoroutineState::DEAD;
    } catch (const std::exception& e) {
        std::cerr << "Goroutine " << id << " crashed: " << e.what() << std::endl;
        state = GoroutineState::DEAD;
    }
}

// EventLoop implementation
EventLoop::EventLoop() : maxThreads(std::thread::hardware_concurrency()), freeThreads(0) {
    if (maxThreads == 0) maxThreads = 4; // Fallback
    freeThreads.store(maxThreads);
    std::cout << "EventLoop initialized with " << maxThreads << " max threads" << std::endl;
}

EventLoop::~EventLoop() {
    shutdown();
}

void EventLoop::spawnGoroutine(std::function<void()> entryPoint) {
    auto goroutine = std::make_shared<Goroutine>(std::move(entryPoint));
    
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        pendingTasks.push(goroutine);
    }
    
    // Wake up a worker thread
    workAvailable.notify_one();
    
    std::cout << "Spawned goroutine " << goroutine->id << std::endl;
}

void EventLoop::addTimer(std::chrono::milliseconds delay, std::function<void()> callback) {
    auto expireTime = std::chrono::steady_clock::now() + delay;
    
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        unexpiredTimers.push({expireTime, std::move(callback)});
    }
    
    workAvailable.notify_one();
}

void EventLoop::processExpiredTimers() {
    auto now = std::chrono::steady_clock::now();
    
    std::lock_guard<std::mutex> lock(queueMutex);
    
    // Process all expired timers directly - no separate queue
    while (!unexpiredTimers.empty() && unexpiredTimers.top().expireTime <= now) {
        auto timer = unexpiredTimers.top();
        unexpiredTimers.pop();
        
        // Execute timer callback immediately (may spawn new goroutines)
        timer.callback();
    }
}

void EventLoop::runTask(std::shared_ptr<Goroutine> task) {
    // Decrement free threads count
    freeThreads--;
    
    std::thread([this, task]() {
        std::cout << "Worker thread running goroutine " << task->id << std::endl;
        task->run();
        std::cout << "Goroutine " << task->id << " finished" << std::endl;
        
        // Increment free threads count when done
        freeThreads++;
        workAvailable.notify_one();
    }).detach();
}

void EventLoop::run() {
    std::cout << "Starting EventLoop main loop" << std::endl;
    
    while (running) {
        bool tasksWereProcessed = false;
        
        // 1. Check and process expired timers
        processExpiredTimers();
        
        // 2. Fire off tasks to available processors
        std::vector<std::shared_ptr<Goroutine>> tasksToRun;
        
        // Lock once, grab up to freeThreads tasks, then unlock
        {
            std::lock_guard<std::mutex> lock(queueMutex);
            
            size_t availableThreads = freeThreads.load();
            size_t tasksToGrab = std::min(availableThreads, pendingTasks.size());
            
            for (size_t i = 0; i < tasksToGrab; ++i) {
                tasksToRun.push_back(pendingTasks.front());
                pendingTasks.pop();
            }
        }
        
        // Fire off all grabbed tasks (outside of lock)
        for (auto& task : tasksToRun) {
            runTask(task);
            tasksWereProcessed = true;
        }
        
        // 3. If ANY tasks were processed, immediately continue
        if (tasksWereProcessed) {
            continue;
        }
        
        // 4. If no tasks were done, check if we have any work left
        bool hasWork = false;
        {
            std::lock_guard<std::mutex> lock(queueMutex);
            hasWork = !pendingTasks.empty() || !unexpiredTimers.empty();
        }
        
        if (!hasWork) {
            std::cout << "No more work, shutting down event loop" << std::endl;
            break;
        }
        
        // Wait for either new work or next timer
        {
            std::unique_lock<std::mutex> lock(queueMutex);
            
            if (unexpiredTimers.empty()) {
                // No timers, just wait for new tasks
                workAvailable.wait(lock, [this]() { 
                    return !running || !pendingTasks.empty(); 
                });
            } else {
                // Wait until next timer or new task
                auto nextTimerExpiry = unexpiredTimers.top().expireTime;
                workAvailable.wait_until(lock, nextTimerExpiry, [this]() { 
                    return !running || !pendingTasks.empty(); 
                });
            }
        }
    }
    
    shutdown();
}

void EventLoop::shutdown() {
    std::cout << "Shutting down EventLoop" << std::endl;
    running = false;
    workAvailable.notify_all();
    
    // Wait for all threads to finish
    while (freeThreads.load() < maxThreads) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    std::cout << "All threads finished" << std::endl;
}

EventLoop& EventLoop::getInstance() {
    static EventLoop instance;
    return instance;
}

// C runtime functions
extern "C" {
    void runtime_spawn_goroutine(void (*func)(void*), void* args, size_t argsSize) {
        // Create a lambda that captures the function and arguments
        auto entryPoint = [func, args, argsSize]() {
            // Call the function with arguments
            func(args);
        };
        
        EventLoop::getInstance().spawnGoroutine(std::move(entryPoint));
    }
    
    void runtime_start_event_loop() {
        std::cout << "Starting event loop" << std::endl;
        EventLoop::getInstance().run();
    }
    
    void runtime_shutdown() {
        EventLoop::getInstance().shutdown();
    }
}