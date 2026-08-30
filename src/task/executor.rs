// ============================================================
// task/executor.rs
// A waker-driven task executor.
//
// A naive executor would just poll every task on every loop iteration,
// busy-spinning even when nothing has anything new to do. This one instead
// gives each task a `Waker` that pushes the task's ID back onto a ready
// queue when something wakes it (e.g. a keyboard interrupt delivering a new
// scancode); the executor only polls tasks that are actually in that queue,
// and `hlt`s the CPU when the queue is empty.
// ============================================================

use super::{Task, TaskId};
use alloc::{collections::BTreeMap, sync::Arc, task::Wake};
use core::task::{Context, Poll, Waker};
use crossbeam_queue::ArrayQueue;

/// Maximum number of tasks that can be simultaneously queued as "ready to
/// poll". Sized generously relative to how many tasks this kernel spawns;
/// if it's ever exceeded, `wake_task`/`spawn` panic rather than silently
/// dropping a wakeup.
const MAX_QUEUED_TASKS: usize = 128;

struct TaskWaker {
    task_id: TaskId,
    task_queue: Arc<ArrayQueue<TaskId>>,
}

impl TaskWaker {
    fn new(task_id: TaskId, task_queue: Arc<ArrayQueue<TaskId>>) -> Waker {
        Waker::from(Arc::new(TaskWaker {
            task_id,
            task_queue,
        }))
    }

    fn wake_task(&self) {
        self.task_queue
            .push(self.task_id)
            .expect("task_queue full");
    }
}

impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        self.wake_task();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wake_task();
    }
}

pub struct Executor {
    tasks: BTreeMap<TaskId, Task>,
    task_queue: Arc<ArrayQueue<TaskId>>,
    waker_cache: BTreeMap<TaskId, Waker>,
}

impl Executor {
    pub fn new() -> Self {
        Executor {
            tasks: BTreeMap::new(),
            task_queue: Arc::new(ArrayQueue::new(MAX_QUEUED_TASKS)),
            waker_cache: BTreeMap::new(),
        }
    }

    pub fn spawn(&mut self, task: Task) {
        let task_id = task.id;
        if self.tasks.insert(task_id, task).is_some() {
            panic!("task with same ID already in tasks");
        }
        self.task_queue.push(task_id).expect("task_queue full");
    }

    fn run_ready_tasks(&mut self) {
        // Destructure so the closure below can mutably borrow `waker_cache`
        // while `task_queue` is borrowed immutably for `.clone()`.
        let Self {
            tasks,
            task_queue,
            waker_cache,
        } = self;

        while let Some(task_id) = task_queue.pop() {
            let task = match tasks.get_mut(&task_id) {
                Some(task) => task,
                None => continue, // task already completed and was removed
            };
            let waker = waker_cache
                .entry(task_id)
                .or_insert_with(|| TaskWaker::new(task_id, task_queue.clone()));
            let mut context = Context::from_waker(waker);
            match task.poll(&mut context) {
                Poll::Ready(()) => {
                    tasks.remove(&task_id);
                    waker_cache.remove(&task_id);
                }
                Poll::Pending => {}
            }
        }
    }

    /// Halt the CPU until the next interrupt if there's nothing ready to
    /// poll. Interrupts are disabled first so a wakeup can't land between
    /// the emptiness check and the `hlt` (which would mean the wakeup gets
    /// missed and we `hlt` anyway); `enable_and_hlt` re-enables and halts as
    /// a single atomic step, so no interrupt is lost.
    fn sleep_if_idle(&self) {
        use x86_64::instructions::interrupts::{self, enable_and_hlt};

        interrupts::disable();
        if self.task_queue.is_empty() {
            enable_and_hlt();
        } else {
            interrupts::enable();
        }
    }

    pub fn run(&mut self) -> ! {
        loop {
            self.run_ready_tasks();
            self.sleep_if_idle();
        }
    }
}
