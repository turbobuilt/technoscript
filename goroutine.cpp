#include "goroutine.h"
#include "lockfree_queue.h"
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
    // Use lock-free queue for efficient re-scheduling
    EventLoop::getInstance().taskQueue.enqueue(new std::shared_ptr<Goroutine>(shared_from_this()));
}

// EventLoop implementation
EventLoop::EventLoop() : maxWorkers(std::thread::hardware_concurrency()) {
    if (maxWorkers == 0) maxWorkers = 4; // Fallback
    std::cout << "EventLoop initialized with max " << maxWorkers << " workers (lazy instantiation)" << std::endl;
}

EventLoop::~EventLoop() {
    shutdown();
}

void EventLoop::spawnGoroutine(std::function<void()> entryPoint) {
    auto goroutine = std::make_shared<Goroutine>(std::move(entryPoint));
    
    // Try to assign to a sleeping worker first
    if (!assignTaskToSleepingWorker(goroutine)) {
        // No sleeping workers, add to lock-free task queue
        taskQueue.enqueue(new std::shared_ptr<Goroutine>(goroutine));
        
        // Create worker thread if we need more capacity
        createWorkerIfNeeded();
        
        // Wake up sleeping workers
        wakeupSleepingWorkers(1);
    }
    
    std::cout << "Spawned goroutine " << goroutine->id << std::endl;
}

void EventLoop::addTimer(std::chrono::milliseconds delay, std::function<void()> callback) {
    auto expireTime = std::chrono::steady_clock::now() + delay;
    
    {
        std::lock_guard<std::mutex> lock(timerMutex);
        unexpiredTimers.emplace(expireTime, std::move(callback));
    }
    
    std::cout << "Timer scheduled for " << delay.count() << "ms from now" << std::endl;
    
    // Wake up sleeping workers in case they need to process expired timers
    wakeupSleepingWorkers(1);
}

void EventLoop::moveExpiredTimersToQueue() {
    auto now = std::chrono::steady_clock::now();
    
    std::lock_guard<std::mutex> lock(timerMutex);
    
    // Efficiently move all expired timers from priority queue to expired timer queue
    while (!unexpiredTimers.empty() && unexpiredTimers.top().expireTime <= now) {
        const auto& timer = unexpiredTimers.top();
        
        // Move callback to expired timer queue for processing
        expiredTimerQueue.enqueue(new ExpiredTimer(std::move(const_cast<TimerTask&>(timer).callback)));
        totalTimersProcessed.fetch_add(1, std::memory_order_relaxed);
        
        unexpiredTimers.pop();
    }
}

std::shared_ptr<Goroutine> EventLoop::checkExpiredTimers() {
    // Check if we have any expired timers ready to execute
    auto expiredTimerPtr = expiredTimerQueue.dequeue();
    if (expiredTimerPtr) {
        ExpiredTimer* expiredTimer = expiredTimerPtr;
        
        // Convert timer callback to goroutine for unified execution
        auto goroutine = std::make_shared<Goroutine>(std::move(expiredTimer->callback));
        
        delete expiredTimer;  // Clean up memory
        return goroutine;
    }
    
    return nullptr; // No expired timers ready
}

void EventLoop::createWorkerIfNeeded() {
    size_t currentActive = activeWorkers.load();
    size_t currentSleeping = sleepingWorkers.load();
    
    // Only create new worker if all workers are busy/sleeping and we haven't hit the limit
    if (currentSleeping == currentActive && currentActive < maxWorkers) {
        // Try to atomically increment activeWorkers
        if (activeWorkers.compare_exchange_strong(currentActive, currentActive + 1)) {
            uint32_t workerId = static_cast<uint32_t>(currentActive);
            auto worker = std::make_unique<WorkerThread>(workerId);
            
            // Create the worker thread
            worker->thread = std::make_unique<std::thread>([this, workerId]() {
                workerThreadFunction(workerId);
            });
            
            workerThreads.push_back(std::move(worker));
            std::cout << "Created worker thread " << workerId << " (total: " << (currentActive + 1) << ")" << std::endl;
        }
    }
}

void EventLoop::wakeupSleepingWorkers(size_t count) {
    if (sleepingWorkers.load() > 0) {
        std::lock_guard<std::mutex> lock(sleepMutex);
        // Wake up the requested number of workers (or all if count is larger)
        for (size_t i = 0; i < count; ++i) {
            workerWakeup.notify_one();
        }
    }
}

bool EventLoop::assignTaskToSleepingWorker(std::shared_ptr<Goroutine> task) {
    std::lock_guard<std::mutex> lock(sleepMutex);
    
    // Find a sleeping worker to assign the task to
    for (auto& worker : workerThreads) {
        if (worker->state.load() == WorkerState::SLEEPING && worker->assignedTask == nullptr) {
            // Assign task and wake up this specific worker
            worker->assignedTask = task;
            workerWakeup.notify_one();
            return true;
        }
    }
    return false; // No sleeping workers available
}

void EventLoop::workerThreadFunction(uint32_t workerId) {
    std::cout << "Worker " << workerId << " started" << std::endl;
    
    std::shared_ptr<Goroutine> task = nullptr;
    
    // Get initial task from queues
    task = checkExpiredTimers();
    if (task == nullptr) {
        auto taskPtr = taskQueue.dequeue();
        if (taskPtr) {
            task = *taskPtr;
            delete taskPtr;
        }
    }
    
    // High-performance loop: while (task != null) { run, check, sleep if needed }
    while (task != nullptr) {
        // Mark worker as running for monitoring
        if (workerId < workerThreads.size()) {
            workerThreads[workerId]->state = WorkerState::RUNNING;
        }
        
        // Set this goroutine as the current executing context
        currentExecutingGoroutine = task;
        
        // Execute the goroutine
        task->run();
        totalTasksProcessed.fetch_add(1, std::memory_order_relaxed);
        
        // Clear current goroutine context
        currentExecutingGoroutine = nullptr;
        task = nullptr; // Clear the task reference
        
        // Check for more work - expired timers first (higher priority)
        task = checkExpiredTimers();
        if (task != nullptr) {
            continue; // Found timer task, continue loop
        }
        
        // Check global task queue for more work
        auto taskPtr = taskQueue.dequeue();
        if (taskPtr) {
            task = *taskPtr;
            delete taskPtr;
            continue; // Found task, continue loop
        }
        
        // No work found - go to sleep and wait for main thread to assign task
        if (workerId < workerThreads.size()) {
            workerThreads[workerId]->state = WorkerState::SLEEPING;
        }
        
        sleepingWorkers.fetch_add(1, std::memory_order_acq_rel);
        
        {
            std::unique_lock<std::mutex> lock(sleepMutex);
            
            // Notify main loop that we're going to sleep
            mainLoopWakeup.notify_one();
            
            // Wait for main thread to assign us a task and wake us up
            workerWakeup.wait(lock, [this, workerId]() {
                // Wake up if we have an assigned task or shutdown
                return (workerId < workerThreads.size() && 
                        workerThreads[workerId]->assignedTask != nullptr);
            });
        }
        
        sleepingWorkers.fetch_sub(1, std::memory_order_acq_rel);
        
        // Get the task assigned by main thread (or nullptr for shutdown)
        if (workerId < workerThreads.size()) {
            task = workerThreads[workerId]->assignedTask;
            workerThreads[workerId]->assignedTask = nullptr; // Clear assignment
        }
        
        // Continue loop with assigned task (or exit if task == nullptr)
    }
    
    std::cout << "Worker " << workerId << " shutting down" << std::endl;
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
        
        // Clean up resolved promise immediately for better memory usage
        promises.erase(it);
    }
    
    // Resume the goroutine directly through the task system for unified scheduling
    if (goroutineToResume) {
        goroutineToResume->resume(value);
        // Wake up a sleeping worker to handle the resumed goroutine
        wakeupSleepingWorkers(1);
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
    
    while (true) {
        // Efficiently move expired timers to the expired queue
        moveExpiredTimersToQueue();
        
        // Check work availability efficiently 
        bool hasExpiredTimers = !expiredTimerQueue.empty();
        bool hasTasks = !taskQueue.empty();
        bool hasUnexpiredTimers = false;
        {
            std::lock_guard<std::mutex> lock(timerMutex);
            hasUnexpiredTimers = !unexpiredTimers.empty();
        }
        
        bool hasWork = hasExpiredTimers || hasTasks || hasUnexpiredTimers;
        
        size_t currentSleeping = sleepingWorkers.load(std::memory_order_acquire);
        size_t currentActive = activeWorkers.load(std::memory_order_acquire);
        
        // Efficient worker management
        if (hasWork && currentSleeping > 0) {
            // We have work and sleeping workers - wake them up
            wakeupSleepingWorkers(std::min(currentSleeping, static_cast<size_t>(2))); // Wake up to 2 workers
        }
        
        // Create more workers if all are busy/sleeping and we're under the limit
        if (currentSleeping == currentActive && hasWork && currentActive < maxWorkers) {
            createWorkerIfNeeded();
        }
        
        // If all threads are busy working, wait efficiently
        if (currentSleeping == 0 && currentActive > 0) {
            // Wait for workers to go to sleep or for new work to arrive
            std::unique_lock<std::mutex> lock(sleepMutex);
            mainLoopWakeup.wait_for(lock, std::chrono::milliseconds(50), [this]() {
                return sleepingWorkers.load() > 0;
            });
            continue;
        }
        
        // If we have no work and all workers are sleeping, check for shutdown conditions
        if (!hasWork && currentSleeping == currentActive && currentActive > 0) {
            // Brief wait to allow for any incoming work before shutting down
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            
            // Double-check for work after the brief wait
            moveExpiredTimersToQueue();
            bool stillHasWork = !expiredTimerQueue.empty() || !taskQueue.empty();
            {
                std::lock_guard<std::mutex> lock(timerMutex);
                stillHasWork = stillHasWork || !unexpiredTimers.empty();
            }
            
            if (!stillHasWork) {
                std::cout << "No work and all workers sleeping, shutting down event loop" << std::endl;
                break;
            }
        }
        
        // If we have no workers at all and no work, shut down
        if (currentActive == 0 && !hasWork) {
            std::cout << "No workers and no work, shutting down event loop" << std::endl;
            break;
        }
        
        // Adaptive pause based on system state
        if (!hasWork) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        } else {
            std::this_thread::yield(); // Just yield CPU if there's work
        }
    }
    
    shutdown();
}

void EventLoop::shutdown() {
    std::cout << "Shutting down EventLoop" << std::endl;
    running.store(false);
    
    // Wake up all sleeping worker threads so they can see the shutdown signal
    wakeupSleepingWorkers(maxWorkers);
    
    // Wait for all worker threads to finish
    for (auto& worker : workerThreads) {
        if (worker->thread && worker->thread->joinable()) {
            std::cout << "Waiting for worker " << worker->id << " to finish..." << std::endl;
            worker->thread->join();
        }
    }
    
    workerThreads.clear();
    activeWorkers.store(0);
    sleepingWorkers.store(0);
    
    std::cout << "All worker threads finished. Tasks processed: " << totalTasksProcessed.load() 
              << ", Timers processed: " << totalTimersProcessed.load() << std::endl;
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
        
        // Schedule the promise resolution using the event loop's timer system
        // This simulates async I/O completion without blocking worker threads
        eventLoop.addTimer(std::chrono::milliseconds(milliseconds), [promiseId, milliseconds, &eventLoop]() {
            std::cout << "Sleep timer expired, resolving promise " << promiseId << std::endl;
            eventLoop.resolvePromise(promiseId, milliseconds);
        });
        
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