// ============================================================
// task/mod.rs
// Cooperative multitasking: async tasks polled by an executor.
// This is single-privilege (ring 0) multitasking — every task runs in
// kernel context and voluntarily yields via `.await`. It has no memory
// isolation between tasks; it's the stepping stone toward real process
// isolation (separate address spaces, ring 3, a scheduler), not a
// replacement for it.
// ============================================================

use alloc::boxed::Box;
use core::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
};

pub mod executor;
pub mod keyboard;

/// A unique identifier for a spawned task, used to look it up in the
/// executor's task map and to route wakeups back to the right task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TaskId(u64);

impl TaskId {
    fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        TaskId(NEXT_ID.fetch_add(1, Ordering::Relaxed))
    }
}

/// A single async task: a boxed, pinned future plus the identity used to
/// schedule it. Boxing erases the concrete future type so the executor can
/// hold a heterogeneous collection of tasks; pinning is required because
/// futures generated from `async fn` bodies may be self-referential.
pub struct Task {
    id: TaskId,
    future: Pin<Box<dyn Future<Output = ()>>>,
}

impl Task {
    pub fn new(future: impl Future<Output = ()> + 'static) -> Task {
        Task {
            id: TaskId::new(),
            future: Box::pin(future),
        }
    }

    fn poll(&mut self, context: &mut Context) -> Poll<()> {
        self.future.as_mut().poll(context)
    }
}
