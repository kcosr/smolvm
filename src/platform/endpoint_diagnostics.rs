//! Opt-in, bounded endpoint diagnostics. Never changes an operation's result.
//!
//! `SMOLVM_ENDPOINT_DIAGNOSTICS=1` enables at most 64 distinct operation events
//! and 16 readiness summaries per process. No environment or payload is logged.

use std::collections::{BTreeMap, HashSet};
use std::fmt::Display;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

type EventKey = (&'static str, &'static str, PathBuf, String);
static ENABLED: OnceLock<bool> = OnceLock::new();
static START: OnceLock<Instant> = OnceLock::new();
static EVENTS: OnceLock<Mutex<HashSet<EventKey>>> = OnceLock::new();
static SUMMARIES: AtomicUsize = AtomicUsize::new(0);

fn enabled() -> bool {
    *ENABLED.get_or_init(|| {
        std::env::var_os("SMOLVM_ENDPOINT_DIAGNOSTICS").as_deref()
            == Some(std::ffi::OsStr::new("1"))
    })
}

fn elapsed_ms() -> u128 {
    START.get_or_init(Instant::now).elapsed().as_millis()
}

fn claim(role: &'static str, op: &'static str, path: &Path, result: String) -> bool {
    let Ok(mut events) = EVENTS.get_or_init(Mutex::default).lock() else {
        return false;
    };
    events.len() < 64 && events.insert((role, op, path.to_path_buf(), result))
}

/// Record an existing I/O operation, retaining its original value and error.
pub fn io<T>(
    role: &'static str,
    op: &'static str,
    path: &Path,
    result: io::Result<T>,
) -> io::Result<T> {
    if enabled() {
        let error = result.as_ref().err();
        let kind = error.map(io::Error::kind);
        let raw_os_error = error.and_then(io::Error::raw_os_error);
        if claim(role, op, path, format!("{kind:?}:{raw_os_error:?}")) {
            tracing::warn!(target: "smolvm::endpoint_diagnostics", pid = std::process::id(), elapsed_ms = elapsed_ms(), role, op,
                path = ?path, path_bytes = path.as_os_str().as_encoded_bytes().len(), ok = result.is_ok(), ?kind, ?raw_os_error,
                "endpoint operation");
        }
    }
    result
}

/// Record a libkrun return code. Negative errno is not WinSock's last error.
pub fn ffi(op: &'static str, path: &Path, port: Option<u32>, listen: Option<bool>, ret: i32) {
    if enabled() && claim("boot", op, path, ret.to_string()) {
        tracing::warn!(target: "smolvm::endpoint_diagnostics", pid = std::process::id(), elapsed_ms = elapsed_ms(), role = "boot", op,
            path = ?path, ?port, ?listen, ret, "libkrun endpoint result");
    }
}

/// Record a non-I/O error without pretending it carries a raw Win32 error.
pub fn failure(role: &'static str, op: &'static str, path: &Path, error: &dyn Display) {
    if enabled() {
        let error: String = error.to_string().chars().take(512).collect();
        if claim(role, op, path, error.clone()) {
            tracing::warn!(target: "smolvm::endpoint_diagnostics", pid = std::process::id(), elapsed_ms = elapsed_ms(), role, op, ?path, %error, "endpoint failure");
        }
    }
}

/// Correlate controller and boot child without logging arguments or credentials.
pub fn launched(
    machine: Option<&str>,
    path: &Path,
    exe: &Path,
    child_pid: i32,
    creation_flags: u32,
) {
    if enabled() && claim("controller", "spawn", path, child_pid.to_string()) {
        tracing::warn!(target: "smolvm::endpoint_diagnostics", pid = std::process::id(), elapsed_ms = elapsed_ms(), role = "controller",
            ?machine, ?path, ?exe, child_pid, creation_flags, "boot child launched");
    }
}

#[derive(Debug, Default)]
struct Stage {
    attempts: u64,
    failures: u64,
    first_error: Option<String>,
    last_error: Option<String>,
}

impl Stage {
    fn observe(&mut self, error: Option<String>) {
        self.attempts = self.attempts.saturating_add(1);
        if let Some(error) = error {
            self.failures = self.failures.saturating_add(1);
            if self.first_error.is_none() {
                self.first_error = Some(error.clone());
            }
            self.last_error = Some(error);
        }
    }
}

struct State {
    path: PathBuf,
    start: Instant,
    outcome: &'static str,
    stages: BTreeMap<&'static str, Stage>,
}

/// Aggregates polling errors rather than logging each readiness iteration.
pub struct Readiness(Option<State>);

impl Readiness {
    /// Disabled mode allocates nothing and adds no filesystem operations.
    pub fn new(path: &Path) -> Self {
        Self(
            (enabled() && SUMMARIES.fetch_add(1, Ordering::Relaxed) < 16).then(|| State {
                path: path.to_path_buf(),
                start: Instant::now(),
                outcome: "early_return",
                stages: BTreeMap::new(),
            }),
        )
    }

    /// Observe an existing operation; retain only first/last bounded error text.
    pub fn observe<T, E: Display>(&mut self, stage: &'static str, result: &Result<T, E>) {
        if let Some(state) = &mut self.0 {
            state.stages.entry(stage).or_default().observe(
                result
                    .as_ref()
                    .err()
                    .map(|e| e.to_string().chars().take(512).collect()),
            );
        }
    }

    /// Count gate outcomes without replacing the gate or trying a connection.
    pub fn socket_exists(&mut self, exists: bool) {
        if let Some(state) = &mut self.0 {
            state
                .stages
                .entry(if exists {
                    "socket_exists_true"
                } else {
                    "socket_exists_false"
                })
                .or_default()
                .observe(None);
        }
    }

    /// Label the existing readiness/timeout outcome without changing it.
    pub fn outcome(&mut self, outcome: &'static str) {
        if let Some(state) = &mut self.0 {
            state.outcome = outcome;
        }
    }
}

impl Drop for Readiness {
    fn drop(&mut self) {
        if let Some(state) = &self.0 {
            // One read-only snapshot while the readiness scope still owns the
            // child. Neither result changes a gate, connection or cleanup.
            let metadata = std::fs::symlink_metadata(&state.path);
            let metadata_error = metadata
                .as_ref()
                .err()
                .map(|e| (e.kind(), e.raw_os_error()));
            let try_exists = state.path.try_exists();
            tracing::warn!(target: "smolvm::endpoint_diagnostics", pid = std::process::id(), role = "controller",
                path = ?state.path, elapsed_ms = state.start.elapsed().as_millis(), outcome = state.outcome,
                stages = ?state.stages, ?metadata_error, ?try_exists, "readiness summary");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_failures_keep_counts_and_only_first_last_errors() {
        let mut stage = Stage::default();
        stage.observe(None);
        for _ in 0..10_000 {
            stage.observe(Some("first".into()));
        }
        stage.observe(Some("last".into()));
        assert_eq!(stage.attempts, 10_002);
        assert_eq!(stage.failures, 10_001);
        assert_eq!(stage.first_error.as_deref(), Some("first"));
        assert_eq!(stage.last_error.as_deref(), Some("last"));
    }
}
