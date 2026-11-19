//! Graceful shutdown handling for Gateway-managed subprocesses.
//!
//! Listens for SIGTERM/SIGINT and sets a shutdown flag.
//! The HTTP server checks this flag before accepting new requests
//! and waits for in-flight requests to complete.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Shared shutdown signal.
pub struct Shutdown {
    flag: AtomicBool,
}

impl Shutdown {
    /// Create a new shutdown signal (initially not shutting down).
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            flag: AtomicBool::new(false),
        })
    }

    /// Check if shutdown has been requested.
    pub fn is_shutting_down(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }

    /// Request shutdown.
    pub fn request(&self) {
        self.flag.store(true, Ordering::Relaxed);
        tracing::info!("Shutdown requested");
    }
}

/// Install signal handlers for SIGTERM and SIGINT.
///
/// On Windows, only SIGINT (Ctrl+C) is supported.
/// On Unix, both SIGTERM and SIGINT are handled.
pub fn install_signal_handlers(shutdown: Arc<Shutdown>) {
    #[cfg(unix)]
    {
        use signal_hook::consts::{SIGINT, SIGTERM};

        // Use Signals iterator in background threads for reliable cross-platform handling
        let shutdown_term = shutdown.clone();
        std::thread::spawn(move || {
            let mut sigs = signal_hook::iterator::Signals::new([SIGTERM])
                .expect("Failed to create SIGTERM signal iterator");
            if sigs.forever().next().is_some() {
                shutdown_term.request();
            }
        });

        let shutdown_int = shutdown.clone();
        std::thread::spawn(move || {
            let mut sigs = signal_hook::iterator::Signals::new([SIGINT])
                .expect("Failed to create SIGINT signal iterator");
            if sigs.forever().next().is_some() {
                shutdown_int.request();
            }
        });
    }

    #[cfg(windows)]
    {
        // On Windows, use tokio's Ctrl+C handler
        let shutdown_ctrlc = shutdown.clone();
        tokio::spawn(async move {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler");
            shutdown_ctrlc.request();
        });
    }
}
