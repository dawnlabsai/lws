//! Shared Tokio runtime for blocking Midnight indexer/prover/submit work.

use std::future::Future;
use std::sync::OnceLock;

static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

/// Process-wide multi-thread runtime for synchronous Midnight call sites.
pub fn runtime() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("ows-midnight")
            .build()
            .expect("failed to create Midnight tokio runtime")
    })
}

/// Run an async future on the shared runtime (blocking the current thread).
pub fn block_on<F>(future: F) -> F::Output
where
    F: Future,
{
    runtime().block_on(future)
}
