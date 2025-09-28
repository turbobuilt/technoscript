#include "goroutine.h"
#include <iostream>
#include <algorithm>
#include <cstring>

// Static member initialization
uint64_t Goroutine::nextId = 0;
uint64_t EventLoop::nextPromiseId = 1;

// Current executing goroutine (thread-local)
thread_local std::shared_ptr<Goroutine> currentExecutingGoroutine = nullptr;

// Goroutine implementation
void Goroutine::run() {
    if (state != GoroutineState::READY && state != GoroutineState::AWAITING_PROMISE) {
        return;
    }
    
    state = GoroutineState::RUNNING;
    
    try {
        // Set up stack context and run the goroutine
        if (setjmp(context->registers) == 0) {
            // First time - set up stack and call entry point
            entryPoint();
        }
        // If we return here via longjmp, check if we were resumed from await
        else if (state == GoroutineState::AWAITING_PROMISE) {
            // We were resumed from an await - continue execution
            // The promise result is already stored in promiseResolvedValue
            return; // Let the goroutine continue from where it left off
        }
        
        // If we reach here naturally, the goroutine finished
        state = GoroutineState::DEAD;
    } catch (const std::exception& e) {
        std::cerr << "Goroutine " << id << " crashed: " << e.what() << std::endl;
        state = GoroutineState::DEAD;
    }
}

void Goroutine::suspend(uint64_t promiseId) {
    awaitingPromiseId = promiseId;
    state = GoroutineState::AWAITING_PROMISE;
    // The actual suspension happens via longjmp in the runtime
}

void Goroutine::resume(int64_t resolvedValue) {
    promiseResolvedValue = resolvedValue;
    awaitingPromiseId = 0;
    state = GoroutineState::READY;
    // Re-queue this goroutine for execution
    EventLoop::getInstance().spawnGoroutine([this]() {
        // Use longjmp to resume from where we left off
        longjmp(context->registers, 1);
    });
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
    
    std::cout << "Timer scheduled for " << delay.count() << "ms from now" << std::endl;
    workAvailable.notify_one();
}

void EventLoop::processExpiredTimers() {
    auto now = std::chrono::steady_clock::now();
    
    // Collect all expired timers first, then execute callbacks outside the lock
    std::vector<TimerTask> expiredTimers;
    
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        
        while (!unexpiredTimers.empty() && unexpiredTimers.top().expireTime <= now) {
            expiredTimers.push_back(unexpiredTimers.top());
            unexpiredTimers.pop();
        }
    }
    
    // Execute callbacks outside the lock to avoid deadlock
    for (auto& timer : expiredTimers) {
        std::cout << "Timer expired, executing callback" << std::endl;
        timer.callback();
    }
}

void EventLoop::runTask(std::shared_ptr<Goroutine> task) {
    // Decrement free threads count and increment running goroutines
    freeThreads--;
    runningGoroutines++;
    
    std::thread([this, task]() {
        std::cout << "Worker thread running goroutine " << task->id << std::endl;
        
        // Set this goroutine as the current executing goroutine for this thread
        currentExecutingGoroutine = task;
        
        task->run();
        std::cout << "Goroutine " << task->id << " finished" << std::endl;
        
        // Clear current goroutine
        currentExecutingGoroutine = nullptr;
        
        // Increment free threads count and decrement running goroutines when done
        freeThreads++;
        runningGoroutines--;
        
        // If this was the last running goroutine, notify the event loop to wake up
        if (runningGoroutines.load() == 0) {
            std::cout << "All goroutines finished, notifying event loop" << std::endl;
            workAvailable.notify_one();
        }
    }).detach();
}

uint64_t EventLoop::createPromise() {
    std::lock_guard<std::mutex> lock(promisesMutex);
    uint64_t promiseId = nextPromiseId++;
    promises.emplace(promiseId, Promise(promiseId));
    std::cout << "Created promise " << promiseId << std::endl;
    return promiseId;
}

void EventLoop::resolvePromise(uint64_t promiseId, int64_t value) {
    std::shared_ptr<Goroutine> goroutineToResume = nullptr;
    
    {
        std::lock_guard<std::mutex> lock(promisesMutex);
        auto it = promises.find(promiseId);
        if (it == promises.end()) {
            std::cerr << "Warning: Trying to resolve non-existent promise " << promiseId << std::endl;
            return;
        }
        
        Promise& promise = it->second;
        if (promise.state != Promise::State::PENDING) {
            std::cerr << "Warning: Trying to resolve already resolved promise " << promiseId << std::endl;
            return;
        }
        
        promise.state = Promise::State::RESOLVED;
        promise.resolvedValue = value;
        goroutineToResume = promise.waitingGoroutine;
        
        std::cout << "Resolved promise " << promiseId << " with value " << value << std::endl;
        
        // Clean up resolved promise
        promises.erase(it);
    }
    
    // Resume the goroutine if one was waiting
    if (goroutineToResume) {
        std::cout << "Resuming goroutine " << goroutineToResume->id << " from promise resolution" << std::endl;
        goroutineToResume->resume(value);
    }
}

int64_t EventLoop::awaitPromise(uint64_t promiseId, std::shared_ptr<Goroutine> currentGoroutine) {
    if (!currentGoroutine) {
        throw std::runtime_error("Cannot await promise: no current goroutine provided");
    }
    
    {
        std::lock_guard<std::mutex> lock(promisesMutex);
        auto it = promises.find(promiseId);
        if (it == promises.end()) {
            throw std::runtime_error("Cannot await non-existent promise " + std::to_string(promiseId));
        }
        
        Promise& promise = it->second;
        if (promise.state == Promise::State::RESOLVED) {
            // Promise already resolved, return value immediately
            int64_t result = promise.resolvedValue;
            promises.erase(it);  // Clean up
            return result;
        }
        
        // Promise is still pending, register goroutine and suspend
        promise.waitingGoroutine = currentGoroutine;
    }
    
    std::cout << "Goroutine " << currentGoroutine->id << " awaiting promise " << promiseId << std::endl;
    currentGoroutine->suspend(promiseId);
    
    // When we reach here, the goroutine has been resumed and the value is in promiseResolvedValue
    return currentGoroutine->promiseResolvedValue;
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
        
        // 3. If ANY tasks were processed, immediately continue (busy server)
        if (tasksWereProcessed) {
            continue;
        }
        
        // 4. No tasks were processed this iteration - check if we should shut down
        size_t currentRunningGoroutines = runningGoroutines.load();
        bool hasWork = false;
        {
            std::lock_guard<std::mutex> lock(queueMutex);
            hasWork = !pendingTasks.empty() || !unexpiredTimers.empty();
        }
        
        // Only shut down if we have no work AND no goroutines are running
        if (!hasWork && currentRunningGoroutines == 0) {
            std::cout << "No more work and all goroutines finished, shutting down event loop" << std::endl;
            break;
        }
        
        // We're idle (no tasks processed) - wait for work or timers
        {
            std::unique_lock<std::mutex> lock(queueMutex);
            
            if (unexpiredTimers.empty()) {
                // No timers, just wait for new tasks or goroutines to finish
                workAvailable.wait(lock, [this]() { 
                    return !running || !pendingTasks.empty() || runningGoroutines.load() == 0; 
                });
            } else {
                // Wait until next timer or new task or goroutines finish
                auto nextTimerExpiry = unexpiredTimers.top().expireTime;
                workAvailable.wait_until(lock, nextTimerExpiry, [this]() { 
                    return !running || !pendingTasks.empty() || runningGoroutines.load() == 0; 
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
    uint64_t runtime_sleep(int64_t milliseconds) {
        auto& eventLoop = EventLoop::getInstance();
        uint64_t promiseId = eventLoop.createPromise();
        
        std::cout << "runtime_sleep: Created promise " << promiseId << " for " << milliseconds << "ms" << std::endl;
        
        // Schedule a background task to resolve the promise after the delay
        // This simulates async I/O completion
        std::thread([promiseId, milliseconds, &eventLoop]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
            std::cout << "Sleep timer expired, resolving promise " << promiseId << std::endl;
            eventLoop.resolvePromise(promiseId, milliseconds);
        }).detach();
        
        return promiseId;
    }
    
    int64_t runtime_await_promise(uint64_t promiseId) {
        std::cout << "runtime_await_promise: Awaiting promise " << promiseId << std::endl;
        
        // Get the current executing goroutine
        auto currentGoroutine = currentExecutingGoroutine;
        if (!currentGoroutine) {
            throw std::runtime_error("runtime_await_promise: No current goroutine context");
        }
        
        return EventLoop::getInstance().awaitPromise(promiseId, currentGoroutine);
    }
    
    void runtime_spawn_goroutine(void (*func)(void*), void* args, size_t argsSize) {
        // Create a lambda that captures the function and arguments
        auto entryPoint = [func, args, argsSize]() {
            // Call the function with arguments
            func(args);
        };
        
        EventLoop::getInstance().spawnGoroutine(std::move(entryPoint));
    }
    
    void runtime_set_timeout(void (*func)(void*), void* args, size_t argsSize, int delayMs) {
        // Create a lambda that captures the function and arguments
        auto callback = [func, args, argsSize]() {
            // Spawn the function as a goroutine when timer expires
            auto entryPoint = [func, args, argsSize]() {
                func(args);
            };
            EventLoop::getInstance().spawnGoroutine(std::move(entryPoint));
        };
        
        // Schedule the timer
        EventLoop::getInstance().addTimer(std::chrono::milliseconds(delayMs), std::move(callback));
    }
    
    void runtime_start_event_loop() {
        std::cout << "Starting event loop" << std::endl;
        EventLoop::getInstance().run();
    }
    
    void runtime_shutdown() {
        EventLoop::getInstance().shutdown();
    }
}