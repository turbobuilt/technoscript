goroutines:

1 thread spawns (main thread) that will run an event loop. this will manage all

has 2 queues - work_queue and completed_timer_queue



wake_lock

async_op_complete(op):
  work_queue.push(op)
  wake_lock.unlock()

loop:
  did_work = false
  if complete_time_queue.length > 0:
    run all completed timers
    did_work = true
  if work_queue > 0:
    run all completed work_queues
    did_work = true

  // in busy scenarios may not get to cv wait
  for timer in active_timers:
    if timer not ready
      break
    trigger code

  if did_work
    continue
  if active_timers.length
    cv wait until (first timer expire, lock triggers)
  