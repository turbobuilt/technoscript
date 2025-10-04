#include "goroutine.h"
#include "lockfree_queue.h"
#include "gc.h"
#include <iostream>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <asmjit/asmjit.h>
#include <mutex>

// Static member initialization
uint64_t Goroutine::nextId = 0;
uint64_t EventLoop::nextPromiseId = 1;

// Thread-local current task being processed by this worker thread (thread-local)
thread_local std::shared_ptr<Goroutine> currentTask = nullptr;

// Goroutine implementation
Goroutine::Goroutine(std::function<void()> entry) 
    : id(++nextId), state(GoroutineState::READY), entryPoint(std::move(entry)) {
    context = std::make_unique<GoroutineContext>();
    gcState = std::make_unique<GoroutineGCState>();
}

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
    // Note: Goroutine is re-enqueued directly by EventLoop::resolvePromise()
    // No need to enqueue here - keeps promise resolution and task queueing unified
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
    
    // Register goroutine in the global registry for GC
    {
        std::lock_guard<std::mutex> lock(goroutineRegistryMutex);
        allGoroutines.insert(goroutine);
    }
    
    // Try to assign to a sleeping worker first
    if (!assignTaskToSleepingWorker(goroutine)) {
        // No sleeping workers, add to lock-free task queue
        taskQueue.enqueue(new std::shared_ptr<Goroutine>(goroutine));
        
        // Create worker thread if we need more capacity and assign it this task
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
        // First, try to get a task from the queue to assign to the new worker
        auto taskPtr = taskQueue.dequeue();
        if (!taskPtr) {
            return; // No task available, don't create worker
        }
        
        std::shared_ptr<Goroutine> task = *taskPtr;
        delete taskPtr;
        
        // Try to atomically increment activeWorkers
        if (activeWorkers.compare_exchange_strong(currentActive, currentActive + 1)) {
            uint32_t workerId = static_cast<uint32_t>(currentActive);
            auto worker = std::make_unique<WorkerThread>(workerId);
            
            // Assign the task to the new worker BEFORE starting it
            worker->assignedTask = task;
            // Set state to RUNNING since we're about to start it with a task
            worker->state.store(WorkerState::RUNNING, std::memory_order_release);
            
            // Create the worker thread
            worker->thread = std::make_unique<std::thread>([this, workerId]() {
                workerThreadFunction(workerId);
            });
            
            workerThreads.push_back(std::move(worker));
            std::cout << "Created worker thread " << workerId << " with assigned task (total: " << (currentActive + 1) << ")" << std::endl;
        } else {
            // Failed to create worker, put task back in queue
            taskQueue.enqueue(new std::shared_ptr<Goroutine>(task));
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
            // Assign task and update state synchronously BEFORE waking worker
            worker->assignedTask = task;
            worker->state.store(WorkerState::RUNNING, std::memory_order_release);
            // Decrement sleepingWorkers count atomically when assigning task
            sleepingWorkers.fetch_sub(1, std::memory_order_release);
            workerWakeup.notify_one();
            return true;
        }
    }
    return false; // No sleeping workers available
}

void EventLoop::workerThreadFunction(uint32_t workerId) {
    std::cout << "Worker " << workerId << " started" << std::endl;
    
    // Get the initial task that was assigned to this worker
    currentTask = workerThreads[workerId]->assignedTask;
    workerThreads[workerId]->assignedTask = nullptr; // Clear assignment
    
    if (!currentTask) {
        std::cerr << "ERROR: Worker " << workerId << " started without assigned task!" << std::endl;
        return;
    }
    
    // High-performance loop: while we have a goroutine to execute
    while (currentTask != nullptr) {
        
        // Execute the goroutine (it's already set as current executing context)
        currentTask->run();
        
        // If goroutine finished, remove it from registry
        if (currentTask->isFinished()) {
            std::lock_guard<std::mutex> lock(goroutineRegistryMutex);
            allGoroutines.erase(currentTask);
        }
        
        // Clear current goroutine context after execution
        currentTask = nullptr;
        
        // Check for more work AFTER completing the task
        // Check expired timers first (higher priority)
        currentTask = checkExpiredTimers();
        if (currentTask != nullptr) {
            continue; // Found timer task, continue loop
        }
        
        // Check global task queue for more work
        auto taskPtr = taskQueue.dequeue();
        if (taskPtr) {
            currentTask = *taskPtr;
            delete taskPtr;
            continue; // Found task, continue loop
        }
        
        // No work found - go to sleep and wait for main thread to assign task
        workerThreads[workerId]->state.store(WorkerState::SLEEPING, std::memory_order_release);
        
        
        {
            std::unique_lock<std::mutex> lock(sleepMutex);
            sleepingWorkers.fetch_add(1, std::memory_order_acq_rel);
            
            // Notify main loop that we're going to sleep
            mainLoopWakeup.notify_one();
            
            // Wait for main thread to assign us a task and wake us up
            workerWakeup.wait(lock, [this, workerId]() {
                // Wake up if we have an assigned task or shutdown
                return workerThreads[workerId]->assignedTask != nullptr || !running.load();
            });
        }
        
        // Get the task assigned by main thread (or nullptr for shutdown)
        currentTask = workerThreads[workerId]->assignedTask;
        workerThreads[workerId]->assignedTask = nullptr; // Clear assignment
        
        // Continue loop with assigned task (or exit if nullptr)
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

// Promise resolution is unified with the task queue:
// - Pending promises are stored in the promises map for O(1) lookup by ID
// - When resolved, the waiting goroutine is enqueued directly to taskQueue
// - There is no separate "promise queue" - resolved promises ARE tasks

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
    
    // Resume the goroutine and enqueue it directly to the task queue
    // This unifies the promise system with the task queue - when a promise resolves,
    // it becomes a task to execute. No separate promise queue needed.
    if (goroutineToResume) {
        goroutineToResume->promiseResolvedValue = value;
        goroutineToResume->awaitingPromiseId = 0;
        goroutineToResume->state = GoroutineState::READY;
        
        // Enqueue directly to task queue - this IS the task queue, unified
        taskQueue.enqueue(new std::shared_ptr<Goroutine>(goroutineToResume));
        
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
        
        // Assign expired timer tasks to sleeping workers
        while (true) {
            auto timerTask = checkExpiredTimers();
            if (!timerTask) {
                break; // No more expired timers
            }
            
            // Try to assign to a sleeping worker
            if (!assignTaskToSleepingWorker(timerTask)) {
                // No sleeping workers, put back in queue for workers to pick up
                // Convert expired timer back to task queue entry
                taskQueue.enqueue(new std::shared_ptr<Goroutine>(timerTask));
                break;
            }
        }
        
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
    
    std::cout << "All worker threads finished." << std::endl;
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
        
        // Get the current task on this worker thread
        auto currentGoroutine = currentTask;
        if (!currentGoroutine) {
            throw std::runtime_error("runtime_await_promise: No current task context");
        }
        
        return EventLoop::getInstance().awaitPromise(promiseId, currentGoroutine);
    }

    // Trampoline function generation and caching
    namespace {
        // Cache for generated trampoline functions
        std::array<void(*)(void*, void**), 8> trampolines = {nullptr};
        std::once_flag trampolinesInitialized;
        asmjit::JitRuntime trampolineRuntime;  // Persistent runtime for all trampolines
        
        // Generate a trampoline function for a specific parameter count
        void* generateTrampoline(size_t paramCount) {
            using namespace asmjit;
            
            CodeHolder code;
            code.init(trampolineRuntime.environment());
            x86::Assembler a(&code);
            
            // Function signature: void trampoline(void* funcPtr, void** paramArray)
            // rdi = funcPtr, rsi = paramArray
            
            // Save frame pointer
            a.push(x86::rbp);
            a.mov(x86::rbp, x86::rsp);
            
            // Save callee-saved registers we might use
            a.push(x86::rbx);
            a.push(x86::r12);
            a.push(x86::r13);
            a.push(x86::r14);
            a.push(x86::r15);
            
            // Save function pointer and param array
            a.mov(x86::rbx, x86::rdi);  // rbx = funcPtr
            a.mov(x86::r12, x86::rsi); // r12 = paramArray
            
            // x86-64 calling convention: rdi, rsi, rdx, rcx, r8, r9, then stack
            x86::Gp paramRegs[] = {x86::rdi, x86::rsi, x86::rdx, x86::rcx, x86::r8, x86::r9};
            const size_t maxRegParams = 6;
            
            // Load register parameters (up to 6)
            for (size_t i = 0; i < std::min(paramCount, maxRegParams); i++) {
                // Load paramArray[i] into appropriate register
                a.mov(paramRegs[i], x86::qword_ptr(x86::r12, i * 8));
            }
            
            // Handle stack parameters (if paramCount > 6)
            if (paramCount > maxRegParams) {
                // Calculate stack space needed (aligned to 16 bytes)
                size_t stackParams = paramCount - maxRegParams;
                size_t stackSpace = ((stackParams + 1) / 2) * 16; // Align to 16 bytes
                
                // Allocate stack space
                a.sub(x86::rsp, stackSpace);
                
                // Push parameters in reverse order (rightmost first for correct stack layout)
                for (size_t i = paramCount - 1; i >= maxRegParams; i--) {
                    size_t stackOffset = (i - maxRegParams) * 8;
                    a.mov(x86::r13, x86::qword_ptr(x86::r12, i * 8));
                    a.mov(x86::qword_ptr(x86::rsp, stackOffset), x86::r13);
                }
            }
            
            // Call the function
            a.call(x86::rbx);
            
            // Clean up stack if we used it
            if (paramCount > maxRegParams) {
                size_t stackParams = paramCount - maxRegParams;
                size_t stackSpace = ((stackParams + 1) / 2) * 16;
                a.add(x86::rsp, stackSpace);
            }
            
            // Restore callee-saved registers
            a.pop(x86::r15);
            a.pop(x86::r14);
            a.pop(x86::r13);
            a.pop(x86::r12);
            a.pop(x86::rbx);
            
            // Restore frame and return
            a.pop(x86::rbp);
            a.ret();
            
            // Compile and return function pointer
            void* func;
            Error err = trampolineRuntime.add(&func, &code);
            if (err) {
                throw std::runtime_error("Failed to generate trampoline: " + std::string(DebugUtils::errorAsString(err)));
            }
            
            return func;
        }
        
        // Generate a generic trampoline for arbitrary parameter counts (7+)
        void* generateGenericTrampoline() {
            using namespace asmjit;
            
            CodeHolder code;
            code.init(trampolineRuntime.environment());
            x86::Assembler a(&code);
            
            // Function signature: void genericTrampoline(void* funcPtr, void** paramArray, size_t paramCount)
            // rdi = funcPtr, rsi = paramArray, rdx = paramCount
            
            // Save frame pointer
            a.push(x86::rbp);
            a.mov(x86::rbp, x86::rsp);
            
            // Save callee-saved registers
            a.push(x86::rbx);
            a.push(x86::r12);
            a.push(x86::r13);
            a.push(x86::r14);
            a.push(x86::r15);
            
            // Save inputs: rbx = funcPtr, r12 = paramArray, r13 = paramCount
            a.mov(x86::rbx, x86::rdi);
            a.mov(x86::r12, x86::rsi);
            a.mov(x86::r13, x86::rdx);
            
            // x86-64 calling convention registers
            x86::Gp paramRegs[] = {x86::rdi, x86::rsi, x86::rdx, x86::rcx, x86::r8, x86::r9};
            const size_t maxRegParams = 6;
            
            // Load register parameters (up to 6)
            Label skipRegLoop = a.newLabel();
            a.cmp(x86::r13, 0);
            a.je(skipRegLoop);
            
            for (size_t i = 0; i < maxRegParams; i++) {
                a.cmp(x86::r13, i + 1);
                a.jl(skipRegLoop);
                a.mov(paramRegs[i], x86::qword_ptr(x86::r12, i * 8));
            }
            a.bind(skipRegLoop);
            
            // Handle stack parameters (paramCount > 6)
            Label skipStackParams = a.newLabel();
            a.cmp(x86::r13, maxRegParams);
            a.jle(skipStackParams);
            
            // Calculate stack space: (paramCount - 6) aligned to 16 bytes
            a.mov(x86::r14, x86::r13);
            a.sub(x86::r14, maxRegParams);  // r14 = stackParams
            a.add(x86::r14, 1);             // r14 = stackParams + 1
            a.shr(x86::r14, 1);             // r14 = (stackParams + 1) / 2
            a.shl(x86::r14, 4);             // r14 = ((stackParams + 1) / 2) * 16
            a.sub(x86::rsp, x86::r14);      // Allocate stack space
            
            // Copy stack parameters
            a.mov(x86::r15, x86::r13);      // r15 = paramCount (loop counter)
            a.sub(x86::r15, 1);             // r15 = paramCount - 1 (start from last param)
            
            Label stackLoop = a.newLabel();
            Label stackDone = a.newLabel();
            
            a.bind(stackLoop);
            a.cmp(x86::r15, maxRegParams - 1);  // Compare with 5 (last reg param index)
            a.jle(stackDone);
            
            // Calculate stack offset: (paramIndex - 6) * 8
            a.mov(x86::rax, x86::r15);
            a.sub(x86::rax, maxRegParams);
            a.shl(x86::rax, 3);  // * 8
            
            // Copy parameter: stack[offset] = paramArray[paramIndex]
            a.mov(x86::r11, x86::qword_ptr(x86::r12, x86::r15, 3));  // r11 = paramArray[r15]
            a.mov(x86::qword_ptr(x86::rsp, x86::rax), x86::r11);
            
            a.sub(x86::r15, 1);
            a.jmp(stackLoop);
            
            a.bind(stackDone);
            a.bind(skipStackParams);
            
            // Call the function
            a.call(x86::rbx);
            
            // Clean up stack if we used it
            Label skipStackCleanup = a.newLabel();
            a.cmp(x86::r13, maxRegParams);
            a.jle(skipStackCleanup);
            
            // Restore stack: same calculation as allocation
            a.mov(x86::r14, x86::r13);
            a.sub(x86::r14, maxRegParams);
            a.add(x86::r14, 1);
            a.shr(x86::r14, 1);
            a.shl(x86::r14, 4);
            a.add(x86::rsp, x86::r14);
            
            a.bind(skipStackCleanup);
            
            // Restore callee-saved registers
            a.pop(x86::r15);
            a.pop(x86::r14);
            a.pop(x86::r13);
            a.pop(x86::r12);
            a.pop(x86::rbx);
            
            // Restore frame and return
            a.pop(x86::rbp);
            a.ret();
            
            // Compile and return function pointer
            void* func;
            Error err = trampolineRuntime.add(&func, &code);
            if (err) {
                throw std::runtime_error("Failed to generate generic trampoline: " + std::string(DebugUtils::errorAsString(err)));
            }
            
            return func;
        }
        
        // Initialize all trampolines at startup
        void initializeTrampolines() {
            std::cout << "Initializing goroutine trampolines..." << std::endl;
            
            // Generate optimized trampolines for 0-6 parameters
            for (size_t i = 0; i < 7; i++) {
                trampolines[i] = reinterpret_cast<void(*)(void*, void**)>(generateTrampoline(i));
                std::cout << "Generated trampoline for " << i << " parameters" << std::endl;
            }
            
            // Generate generic trampoline for 7+ parameters (stored at index 7)
            trampolines[7] = reinterpret_cast<void(*)(void*, void**)>(generateGenericTrampoline());
            std::cout << "Generated generic trampoline for 7+ parameters" << std::endl;
        }
        
        void(*getTrampoline(size_t paramCount))(void*, void**) {
            // Initialize trampolines once
            std::call_once(trampolinesInitialized, initializeTrampolines);
            
            // Return appropriate trampoline (use generic for 7+)
            if (paramCount < 7) {
                return trampolines[paramCount];
            } else {
                return trampolines[7];  // Generic trampoline
            }
        }
    }
    
    void goroutine_execute(void* funcPtr, void** paramArray, size_t paramCount) {
        // Get the appropriate trampoline and call it
        auto trampoline = getTrampoline(paramCount);
        
        if (paramCount < 7) {
            // Use direct trampoline for 0-6 parameters
            trampoline(funcPtr, paramArray);
        } else {
            // For 7+ parameters, we need to cast to the generic signature
            // The generic trampoline actually has signature void(*)(void*, void**, size_t)
            // but is stored in the array with the base signature for simplicity
            #pragma GCC diagnostic push
            #pragma GCC diagnostic ignored "-Wcast-function-type"
            auto genericTrampoline = reinterpret_cast<void(*)(void*, void**, size_t)>(trampolines[7]);
            #pragma GCC diagnostic pop
            genericTrampoline(funcPtr, paramArray, paramCount);
        }
    }
    
    void runtime_spawn_goroutine(void* funcPtr, void** paramArray, size_t paramCount) {
        // Create a lambda that captures the function and arguments
        auto entryPoint = [funcPtr, paramArray, paramCount]() {
            goroutine_execute(funcPtr, paramArray, paramCount);
            free(paramArray);  // Free parameter array after execution
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