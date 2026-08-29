//! Place a VM process in its own **systemd transient scope** so it survives a
//! `serve` restart.
//!
//! Today a VM is a child process inside `smolvm-node.service`'s delegated cgroup.
//! On `systemctl restart`, a surviving VM left in that cgroup makes systemd fail
//! to recreate the unit (`status=219/CGROUP`) → serve crash-loops. Adopting the
//! VM into its own `smolvm-vm-<id>.scope` (a sibling unit owned by PID1) moves it
//! out of the service cgroup, so serve can restart and reconnect to the still-
//! running VM. See `docs/lossless-serve-restart.md`.
//!
//! Implemented by shelling out to `busctl` (ships with systemd — no D-Bus crate
//! dependency, and absent exactly where scopes wouldn't work anyway). The caller
//! forks the VM normally (retaining stdio/fd/process-group control), then calls
//! [`adopt_into_scope`] on the resulting PID. systemd's `StartTransientUnit`
//! with a `PIDs=` property moves the process into the scope's cgroup and applies
//! the resource caps as unit properties. Scopes auto-remove when their last
//! process exits, so machine stop/delete needs no extra teardown.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

/// Hard wall-clock bound on any single `busctl` call.
///
/// `busctl` is on both VM hot paths — `start` → [`adopt_into_scope`] and
/// `stop`/delete → [`kill_scope`] — and these run on the request-serving blocking
/// pool. systemd's `StartTransientUnit`/`KillUnit` can block for MINUTES when a VM
/// is wedged in an uninterruptible (D) kernel state (its cgroup won't die), and the
/// call had no timeout — so one stuck VM could pin blocking-pool threads until they
/// were exhausted, starving `start`/`exec` across the whole node while `/health`
/// (pure-async, no busctl) stayed green so auto-cordon never fired. This bounds the
/// call so the thread is freed in seconds; the teardown is retried out-of-band
/// instead of hanging the node. See the 2026-07-05 worker-1 wedge.
const BUSCTL_TIMEOUT: Duration = Duration::from_secs(10);

/// Poll cadence while waiting for a `busctl` call to finish. Small relative to the
/// timeout; adds at most one interval of latency to a normal (fast) call.
const BUSCTL_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Run a `busctl` command with a hard wall-clock bound ([`BUSCTL_TIMEOUT`]).
///
/// On timeout the child is killed (busctl is a normal userspace process, so it dies
/// at once, freeing the thread) and a timeout error is returned for the caller to
/// handle out-of-band — never leaving a request-serving thread pinned on a wedged
/// systemd. std-only (no libc) so it compiles on every platform the callers do;
/// busctl's replies are tiny, so leaving stdout/stderr buffered until the poll loop
/// exits can't fill the pipe.
fn busctl_bounded(mut cmd: Command, timeout: Duration) -> Result<Output> {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::agent("vm scope", format!("busctl spawn failed: {e}")))?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(Error::agent(
                        "vm scope",
                        format!(
                            "busctl timed out after {}s (systemd/cgroup wedged)",
                            timeout.as_secs()
                        ),
                    ));
                }
                std::thread::sleep(BUSCTL_POLL_INTERVAL);
            }
            Err(e) => return Err(Error::agent("vm scope", format!("busctl wait failed: {e}"))),
        }
    }
    child
        .wait_with_output()
        .map_err(|e| Error::agent("vm scope", format!("busctl output failed: {e}")))
}

/// Resource caps applied to the VM's scope (as systemd unit properties).
///
/// Mirrors the per-VM cgroup limits set by [`crate::process::place_in_cgroup`]:
/// `MemoryMax` ↔ `memory.max`, `CPUQuotaPerSecUSec` ↔ `cpu.max`, `TasksMax` ↔
/// `pids.max`.
#[derive(Debug, Default, Clone)]
pub struct ScopeCaps {
    /// Hard memory ceiling in bytes (`MemoryMax`). `None` = uncapped.
    pub memory_max_bytes: Option<u64>,
    /// CPU quota in microseconds-of-CPU-time per real second
    /// (`CPUQuotaPerSecUSec`). For N vCPUs uncapped-overcommit, pass
    /// `N * 1_000_000`. `None` = uncapped.
    pub cpu_quota_usec_per_sec: Option<u64>,
    /// Max number of tasks/PIDs (`TasksMax`). `None` = systemd default.
    pub tasks_max: Option<u64>,
}

/// True iff we can actually create system-bus transient scopes here: a systemd
/// host (`/run/systemd/system`, à la `sd_booted()`), `busctl` present, AND we run
/// as root.
///
/// The root check matters: `StartTransientUnit` on the **system** bus needs root
/// (or polkit), and serve runs as root on the cloud worker. Without it, an
/// unprivileged local `serve` would pass the systemd check, enter scope-mode,
/// then have every adopt rejected — leaving VMs uncapped (scope-mode skips the
/// cgroup fallback). Returning false instead routes the caller to direct cgroup
/// placement, which keeps resource caps (it just isn't lossless — fine for dev).
///
/// Non-systemd hosts (macOS dev, OpenRC, bare containers) also return false.
/// Future: support the per-user systemd bus (`busctl --user`) so an unprivileged
/// local serve can still get scopes.
pub fn is_available() -> bool {
    // systemd scopes are a Linux-only concept; never available elsewhere.
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: geteuid() is always-safe (no args, no global state mutation).
        let is_root = unsafe { libc::geteuid() } == 0;
        is_root && Path::new("/run/systemd/system").is_dir() && busctl_path().is_some()
    }
}

/// Locate `busctl` (PATH, then the usual absolute locations — serve may run with
/// a minimal `PATH`).
fn busctl_path() -> Option<PathBuf> {
    for cand in ["/usr/bin/busctl", "/bin/busctl", "/usr/local/bin/busctl"] {
        let p = Path::new(cand);
        if p.exists() {
            return Some(p.to_path_buf());
        }
    }
    // Fall back to PATH resolution via the shell-less which-equivalent.
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join("busctl"))
            .find(|p| p.exists())
    })
}

/// systemd unit names allow `[A-Za-z0-9:_.\-]`; sanitize the machine id and clamp
/// length so the scope name is always valid. Collisions are avoided by the caller
/// using unique machine ids; a dead scope self-removes when its VM exits.
pub fn scope_name(machine_id: &str) -> String {
    let safe: String = machine_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':') {
                c
            } else {
                '_'
            }
        })
        .take(200)
        .collect();
    format!("smolvm-vm-{safe}.scope")
}

/// Adopt an already-forked VM `pid` into its own transient scope with `caps`.
///
/// Returns `Err` if systemd rejects the request (e.g. the PID already exited, or
/// the bus call failed). When scope mode is required, the caller must terminate
/// the unadopted child rather than leave it running without these caps.
pub fn adopt_into_scope(machine_id: &str, pid: i32, caps: &ScopeCaps) -> Result<()> {
    let busctl = busctl_path()
        .ok_or_else(|| Error::agent("vm scope", "busctl not found; cannot create scope"))?;
    adopt_into_scope_with(machine_id, pid, caps, |args| {
        let mut cmd = Command::new(&busctl);
        cmd.args(args);
        busctl_bounded(cmd, BUSCTL_TIMEOUT)
    })
}

fn adopt_into_scope_with<F>(machine_id: &str, pid: i32, caps: &ScopeCaps, mut run: F) -> Result<()>
where
    F: FnMut(&[String]) -> Result<Output>,
{
    let name = scope_name(machine_id);

    // Build the a(sv) property list in busctl's positional encoding:
    //   <prop-name> <variant-type> <variant-value...>
    // PIDs is an array of u32 (`au`): "au <count> <elem...>".
    let mut props: Vec<String> = Vec::new();
    let mut nprops: u32 = 0;

    props.extend(["PIDs".into(), "au".into(), "1".into(), pid.to_string()]);
    nprops += 1;
    props.extend([
        "Description".into(),
        "s".into(),
        format!("smolvm VM {machine_id}"),
    ]);
    nprops += 1;
    if let Some(m) = caps.memory_max_bytes {
        props.extend(["MemoryMax".into(), "t".into(), m.to_string()]);
        nprops += 1;
    }
    if let Some(q) = caps.cpu_quota_usec_per_sec {
        props.extend(["CPUQuotaPerSecUSec".into(), "t".into(), q.to_string()]);
        nprops += 1;
    }
    if let Some(t) = caps.tasks_max {
        props.extend(["TasksMax".into(), "t".into(), t.to_string()]);
        nprops += 1;
    }

    // StartTransientUnit(name: s, mode: s, properties: a(sv), aux: a(sa(sv))).
    // mode "fail": error if the unit already exists (a stale same-name scope must
    // have been GC'd first — it would have been, when its VM exited).
    let mut args: Vec<String> = vec![
        "call".into(),
        "org.freedesktop.systemd1".into(),
        "/org/freedesktop/systemd1".into(),
        "org.freedesktop.systemd1.Manager".into(),
        "StartTransientUnit".into(),
        "ssa(sv)a(sa(sv))".into(),
        name.clone(),
        "fail".into(),
        nprops.to_string(),
    ];
    args.extend(props);
    args.push("0".into()); // empty aux array

    let mut out = run(&args)?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let original_error = format!("StartTransientUnit {name} failed: {}", stderr.trim());
        if unit_exists_error(&stderr) {
            if let Some(state) = loaded_unit_active_state(&name, &mut run)? {
                if matches!(state.as_str(), "failed" | "inactive") {
                    reset_failed_unit(&name, &mut run)?;
                    out = run(&args)?;
                    if out.status.success() {
                        tracing::info!(scope = %name, pid, previous_state = %state,
                            "reset stale transient scope and adopted VM");
                        return Ok(());
                    }
                }
            }
        }
        let retry_stderr = String::from_utf8_lossy(&out.stderr);
        let detail = if retry_stderr.trim().is_empty() {
            original_error
        } else {
            format!("{original_error}; retry failed: {}", retry_stderr.trim())
        };
        return Err(Error::agent("vm scope", detail));
    }
    tracing::info!(scope = %name, pid, "adopted VM into systemd transient scope");
    Ok(())
}

fn unit_exists_error(stderr: &str) -> bool {
    stderr.contains("UnitExists")
        || stderr.contains("already loaded")
        || stderr.contains("already exists")
}

fn quoted_busctl_value(output: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(output).ok()?;
    let start = text.find('"')? + 1;
    let end = text[start..].find('"')? + start;
    Some(text[start..end].to_string())
}

fn loaded_unit_active_state<F>(name: &str, run: &mut F) -> Result<Option<String>>
where
    F: FnMut(&[String]) -> Result<Output>,
{
    let get_unit = vec![
        "call".into(),
        "org.freedesktop.systemd1".into(),
        "/org/freedesktop/systemd1".into(),
        "org.freedesktop.systemd1.Manager".into(),
        "GetUnit".into(),
        "s".into(),
        name.into(),
    ];
    let output = run(&get_unit)?;
    if !output.status.success() {
        return Ok(None);
    }
    let Some(object_path) = quoted_busctl_value(&output.stdout) else {
        return Err(Error::agent("vm scope", "GetUnit returned no object path"));
    };
    let get_state = vec![
        "get-property".into(),
        "org.freedesktop.systemd1".into(),
        object_path,
        "org.freedesktop.systemd1.Unit".into(),
        "ActiveState".into(),
    ];
    let output = run(&get_state)?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(quoted_busctl_value(&output.stdout))
}

fn reset_failed_unit<F>(name: &str, run: &mut F) -> Result<()>
where
    F: FnMut(&[String]) -> Result<Output>,
{
    let args = vec![
        "call".into(),
        "org.freedesktop.systemd1".into(),
        "/org/freedesktop/systemd1".into(),
        "org.freedesktop.systemd1.Manager".into(),
        "ResetFailedUnit".into(),
        "s".into(),
        name.into(),
    ];
    let output = run(&args)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::agent(
            "vm scope",
            format!(
                "ResetFailedUnit {name} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ))
    }
}

/// Resume every process in an adopted VM scope without addressing the child by
/// a potentially reusable numeric PID.
#[cfg(target_os = "linux")]
pub fn continue_scope(machine_id: &str) -> Result<()> {
    let busctl = busctl_path()
        .ok_or_else(|| Error::agent("vm scope", "busctl not found; cannot resume scope"))?;
    signal_scope_with(machine_id, libc::SIGCONT, |args| {
        let mut cmd = Command::new(&busctl);
        cmd.args(args);
        busctl_bounded(cmd, BUSCTL_TIMEOUT)
    })
}

#[cfg(target_os = "linux")]
fn signal_scope_with<F>(machine_id: &str, signal: i32, mut run: F) -> Result<()>
where
    F: FnMut(&[String]) -> Result<Output>,
{
    let name = scope_name(machine_id);
    let args = vec![
        "call".into(),
        "org.freedesktop.systemd1".into(),
        "/org/freedesktop/systemd1".into(),
        "org.freedesktop.systemd1.Manager".into(),
        "KillUnit".into(),
        "ssi".into(),
        name.clone(),
        "all".into(),
        signal.to_string(),
    ];
    let output = run(&args)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::agent(
            "vm scope",
            format!(
                "signal {signal} to {name} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ))
    }
}

/// Force-kill a VM's transient scope: SIGKILL every process in its cgroup.
///
/// This is the AUTHORITATIVE teardown when the pid-based delete can't confirm
/// death — no recorded pid, or a process that outlived SIGKILL-by-pid. The scope
/// owns every process the VM spawned regardless of the pid we happened to record,
/// so killing the cgroup is what stops a stuck/crash-looping VM that would
/// otherwise become an un-deletable orphan (control marks it deleted, the node
/// keeps running it). Returns `Ok(true)` on a successful kill OR a missing scope
/// (already gone == teardown done). Non-Linux / no-busctl hosts return `Ok(false)`
/// — nothing scope-based to stop; the caller falls back to its pid path.
pub fn kill_scope(machine_id: &str) -> Result<bool> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = machine_id;
        Ok(false)
    }
    #[cfg(target_os = "linux")]
    {
        let Some(busctl) = busctl_path() else {
            return Ok(false);
        };
        let name = scope_name(machine_id);
        // KillUnit(name: s, who: s, signal: i): SIGKILL (9) every process in the
        // scope ("all"). SIGKILL is uncatchable, so a wedged VM dies immediately;
        // the emptied scope then self-GCs. `ssi` is the busctl arg signature.
        let mut cmd = Command::new(&busctl);
        cmd.args([
            "call",
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
            "KillUnit",
            "ssi",
            &name,
            "all",
            "9",
        ]);
        let out = busctl_bounded(cmd, BUSCTL_TIMEOUT)?;
        if out.status.success() {
            tracing::info!(scope = %name, "SIGKILLed VM transient scope (forced teardown)");
            return Ok(true);
        }
        // A scope that already exited is not loaded — teardown is effectively done.
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("not loaded")
            || stderr.contains("NoSuchUnit")
            || stderr.contains("not found")
        {
            tracing::debug!(scope = %name, "scope already gone on kill");
            return Ok(true);
        }
        Err(Error::agent(
            "vm scope",
            format!("KillUnit {name} failed: {}", stderr.trim()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn output(success: bool, stdout: &str, stderr: &str) -> Output {
        use std::os::unix::process::ExitStatusExt;
        Output {
            status: std::process::ExitStatus::from_raw(if success { 0 } else { 1 << 8 }),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn adopt_resets_only_failed_stale_scope_then_retries() {
        let mut methods = Vec::new();
        let mut starts = 0;
        let result = adopt_into_scope_with("stale", 4242, &ScopeCaps::default(), |args| {
            let method = args
                .iter()
                .find(|arg| {
                    matches!(
                        arg.as_str(),
                        "StartTransientUnit" | "GetUnit" | "ActiveState" | "ResetFailedUnit"
                    )
                })
                .cloned()
                .unwrap();
            methods.push(method.clone());
            Ok(match method.as_str() {
                "StartTransientUnit" => {
                    starts += 1;
                    if starts == 1 {
                        output(false, "", "UnitExists: Unit already loaded")
                    } else {
                        output(true, "o \"/job/1\"", "")
                    }
                }
                "GetUnit" => output(true, "o \"/org/freedesktop/systemd1/unit/stale\"", ""),
                "ActiveState" => output(true, "s \"failed\"", ""),
                "ResetFailedUnit" => output(true, "", ""),
                _ => unreachable!(),
            })
        });

        result.unwrap();
        assert_eq!(
            methods,
            [
                "StartTransientUnit",
                "GetUnit",
                "ActiveState",
                "ResetFailedUnit",
                "StartTransientUnit"
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn adopt_also_recovers_an_inactive_stale_scope() {
        let mut starts = 0;
        let mut reset = false;
        let result = adopt_into_scope_with("inactive", 4242, &ScopeCaps::default(), |args| {
            if args.iter().any(|arg| arg == "StartTransientUnit") {
                starts += 1;
                return Ok(if starts == 1 {
                    output(false, "", "UnitExists: Unit already loaded")
                } else {
                    output(true, "o \"/job/1\"", "")
                });
            }
            if args.iter().any(|arg| arg == "GetUnit") {
                return Ok(output(
                    true,
                    "o \"/org/freedesktop/systemd1/unit/inactive\"",
                    "",
                ));
            }
            if args.iter().any(|arg| arg == "ActiveState") {
                return Ok(output(true, "s \"inactive\"", ""));
            }
            if args.iter().any(|arg| arg == "ResetFailedUnit") {
                reset = true;
                return Ok(output(true, "", ""));
            }
            unreachable!()
        });

        result.unwrap();
        assert!(reset);
        assert_eq!(starts, 2);
    }

    #[cfg(unix)]
    #[test]
    fn adopt_never_resets_or_retries_an_active_scope() {
        let mut methods = Vec::new();
        let result = adopt_into_scope_with("active", 4242, &ScopeCaps::default(), |args| {
            let method = args
                .iter()
                .find(|arg| {
                    matches!(
                        arg.as_str(),
                        "StartTransientUnit" | "GetUnit" | "ActiveState" | "ResetFailedUnit"
                    )
                })
                .cloned()
                .unwrap();
            methods.push(method.clone());
            Ok(match method.as_str() {
                "StartTransientUnit" => output(false, "", "UnitExists: Unit already loaded"),
                "GetUnit" => output(true, "o \"/org/freedesktop/systemd1/unit/active\"", ""),
                "ActiveState" => output(true, "s \"active\"", ""),
                "ResetFailedUnit" => panic!("an active scope must never be reset"),
                _ => unreachable!(),
            })
        });

        assert!(result.is_err());
        assert_eq!(methods, ["StartTransientUnit", "GetUnit", "ActiveState"]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn adopted_child_is_resumed_through_its_scope_identity() {
        let mut observed = Vec::new();
        signal_scope_with("machine-a", libc::SIGCONT, |args| {
            observed = args.to_vec();
            Ok(output(true, "", ""))
        })
        .unwrap();

        assert_eq!(
            observed,
            vec![
                "call".to_string(),
                "org.freedesktop.systemd1".to_string(),
                "/org/freedesktop/systemd1".to_string(),
                "org.freedesktop.systemd1.Manager".to_string(),
                "KillUnit".to_string(),
                "ssi".to_string(),
                "smolvm-vm-machine-a.scope".to_string(),
                "all".to_string(),
                libc::SIGCONT.to_string(),
            ]
        );
    }

    // A wedged busctl (systemd stuck on a dying cgroup) must not pin the thread:
    // the call is bounded and returns promptly, well under the hang it replaces.
    #[cfg(unix)]
    #[test]
    fn busctl_bounded_kills_a_hung_call() {
        let mut cmd = Command::new("sleep");
        cmd.arg("30"); // stand-in for a busctl call that never returns
        let start = Instant::now();
        let out = busctl_bounded(cmd, Duration::from_millis(150));
        let elapsed = start.elapsed();
        assert!(
            out.is_err(),
            "a call exceeding the bound must error, not hang"
        );
        assert!(
            out.unwrap_err().to_string().contains("timed out"),
            "the error must identify a timeout"
        );
        // Freed in ~the bound, not the child's 30s runtime — a generous ceiling.
        assert!(
            elapsed < Duration::from_secs(2),
            "bounded call took {elapsed:?}; should return near the 150ms bound"
        );
    }

    // A fast call returns its real output and status, unaffected by the bound.
    #[cfg(unix)]
    #[test]
    fn busctl_bounded_returns_fast_call_output() {
        let mut cmd = Command::new("printf");
        cmd.arg("ok");
        let out = busctl_bounded(cmd, Duration::from_secs(5)).expect("fast call");
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout), "ok");
    }

    #[test]
    fn scope_name_sanitizes_and_suffixes() {
        assert_eq!(
            scope_name("machine-abc123"),
            "smolvm-vm-machine-abc123.scope"
        );
        // Illegal chars (slash, space) collapse to underscore.
        assert_eq!(scope_name("a/b c"), "smolvm-vm-a_b_c.scope");
        // Allowed punctuation is preserved.
        assert_eq!(scope_name("m_1.2:3"), "smolvm-vm-m_1.2:3.scope");
    }

    #[test]
    fn scope_name_is_bounded() {
        let long = "x".repeat(500);
        let n = scope_name(&long);
        assert!(n.starts_with("smolvm-vm-"));
        assert!(n.ends_with(".scope"));
        // sanitized body clamped to 200 chars + fixed prefix/suffix.
        assert!(n.len() <= "smolvm-vm-".len() + 200 + ".scope".len());
    }
}
