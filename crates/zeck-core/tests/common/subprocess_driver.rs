//! Subprocess driver for the `argos-scan-helper` and `argos-sweep-helper`
//! test binaries.
//!
//! The driver spawns the helper, parses its JSON-line stdout into typed
//! [`HelperEvent`] values, and exposes:
//!
//!   - [`HelperHandle::wait_for`] — poll until a predicate over the cumulative
//!     event stream is satisfied or a deadline expires.
//!   - [`HelperHandle::sigkill_and_wait`] — deliver `SIGKILL` and confirm
//!     the child died from the signal (not from a clean exit).
//!   - [`HelperHandle::wait_for_exit`] — let the child run to completion,
//!     returning its exit status.
//!
//! Gated on `argos-network` so production builds never link this module.

#![cfg(feature = "argos-network")]
#![allow(dead_code)] // Some helpers are exercised only by R-S27 or only by R-S29.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

/// One JSON event emitted by either helper binary.
///
/// Both helpers share the scan-phase event tags. Sweep-only events
/// (`SweepStarting`, `Broadcast`, `SweepComplete`) appear only from
/// `argos-sweep-helper`.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum HelperEvent {
    Phase {
        phase: String,
    },
    Block {
        scanned_to: u64,
    },
    Discovery {
        account_index: u32,
        pool: String,
        zatoshis: u64,
        address: String,
        at_block_height: u64,
    },
    /// Emitted by `argos-scan-helper` on `ScanPhase::Complete`.
    Complete {
        total_zatoshis: u64,
    },
    /// Emitted by `argos-sweep-helper` on `ScanPhase::Complete`,
    /// before the sweep phase begins.
    ScanComplete {
        total_zatoshis: u64,
    },
    SweepStarting,
    Broadcast {
        source_account: u32,
        txid: Option<String>,
        status: String,
        detail: String,
        confirmed_height: Option<u32>,
    },
    SweepComplete {
        broadcast_count: usize,
    },
    Error {
        message: String,
    },
}

/// Handle to a running helper subprocess.
pub struct HelperHandle {
    child: Child,
    stdout_lines: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    /// Append-only log of every event the helper has emitted so far. The test
    /// can scan this for arbitrary predicates.
    events: Vec<HelperEvent>,
    /// Raw lines that failed to parse as `HelperEvent` (e.g. tracing-subscriber
    /// log output if some library path enabled it). Kept around so test
    /// failures can surface them.
    unparsed: VecDeque<String>,
}

/// Builder for spawning a helper subprocess.
pub struct HelperSpawn {
    binary: PathBuf,
    args: Vec<String>,
    seed: String,
}

impl HelperSpawn {
    /// Begin building a spawn command for the given helper binary path.
    ///
    /// In integration tests, pass `env!("CARGO_BIN_EXE_argos-scan-helper")`
    /// or `env!("CARGO_BIN_EXE_argos-sweep-helper")`.
    pub fn new(binary: impl Into<PathBuf>, seed: impl Into<String>) -> Self {
        Self {
            binary: binary.into(),
            args: Vec::new(),
            seed: seed.into(),
        }
    }

    pub fn arg(mut self, flag: impl Into<String>) -> Self {
        self.args.push(flag.into());
        self
    }

    pub fn arg_value(mut self, flag: impl Into<String>, value: impl Into<String>) -> Self {
        self.args.push(flag.into());
        self.args.push(value.into());
        self
    }

    pub async fn spawn(self) -> std::io::Result<HelperHandle> {
        let mut child = Command::new(&self.binary)
            .args(&self.args)
            .env("ARGOS_TEST_SEED", &self.seed)
            // Keep stderr inherited so any unexpected panics in the helper
            // show up directly in the test output without us having to
            // forward them.
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;

        let stdout = child
            .stdout
            .take()
            .expect("helper child stdout pipe must be present");
        let lines = BufReader::new(stdout).lines();

        Ok(HelperHandle {
            child,
            stdout_lines: lines,
            events: Vec::new(),
            unparsed: VecDeque::new(),
        })
    }
}

impl HelperHandle {
    /// Drain any stdout lines that have arrived since the last call and
    /// append them to the event log. Returns the count of new events.
    async fn drain_available(&mut self) -> std::io::Result<usize> {
        let mut new_events = 0;
        loop {
            // tokio::io::Lines::next_line is async, so we tick it under a
            // zero-duration timeout to drain only what's currently buffered.
            match tokio::time::timeout(Duration::from_millis(0), self.stdout_lines.next_line())
                .await
            {
                Err(_) => break, // no line available right now
                Ok(Ok(Some(line))) => match serde_json::from_str::<HelperEvent>(&line) {
                    Ok(ev) => {
                        self.events.push(ev);
                        new_events += 1;
                    }
                    Err(_) => {
                        self.unparsed.push_back(line);
                    }
                },
                Ok(Ok(None)) => break, // stream closed
                Ok(Err(e)) => return Err(e),
            }
        }
        Ok(new_events)
    }

    /// Poll the helper until `pred` returns `Some(result)` over the current
    /// event log, or until `deadline` expires. The predicate is called every
    /// 50ms.
    pub async fn wait_for<T>(
        &mut self,
        deadline: Instant,
        mut pred: impl FnMut(&[HelperEvent]) -> Option<T>,
    ) -> Result<T, WaitError> {
        loop {
            // Read whatever has arrived, then test the predicate.
            self.drain_available().await.map_err(WaitError::Io)?;
            if let Some(v) = pred(&self.events) {
                return Ok(v);
            }
            if Instant::now() >= deadline {
                return Err(WaitError::Deadline {
                    events: self.events.clone(),
                    unparsed: self.unparsed.iter().cloned().collect(),
                });
            }
            // Also check if the child has already exited — there's no point
            // polling forever if the helper is gone.
            if let Some(status) = self.child.try_wait().map_err(WaitError::Io)? {
                // Drain whatever is left on stdout after the exit.
                let stdout = self.child.stdout.take();
                drop(stdout);
                self.drain_available().await.map_err(WaitError::Io)?;
                if let Some(v) = pred(&self.events) {
                    return Ok(v);
                }
                return Err(WaitError::ChildExited {
                    status,
                    events: self.events.clone(),
                    unparsed: self.unparsed.iter().cloned().collect(),
                });
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Deliver `SIGKILL` to the helper and wait for it to exit. Returns the
    /// raw exit status so the test can confirm the child died from a signal
    /// rather than from a clean exit (which would imply the SIGKILL landed
    /// after the helper had already finished — a test-design bug, not a
    /// production-code property).
    pub async fn sigkill_and_wait(mut self) -> std::io::Result<std::process::ExitStatus> {
        // `Child::start_kill` on tokio sends SIGKILL on Unix.
        self.child.start_kill()?;
        self.child.wait().await
    }

    /// Wait for the helper to exit on its own. Useful for tests that don't
    /// SIGKILL (the second run of R-S27 after resume, the smoke tests).
    pub async fn wait_for_exit(
        mut self,
    ) -> std::io::Result<(std::process::ExitStatus, Vec<HelperEvent>)> {
        let status = self.child.wait().await?;
        // Drain any remaining stdout after exit.
        self.drain_available().await?;
        Ok((status, self.events))
    }

    pub fn events(&self) -> &[HelperEvent] {
        &self.events
    }
}

#[derive(Debug)]
pub enum WaitError {
    Io(std::io::Error),
    Deadline {
        events: Vec<HelperEvent>,
        unparsed: Vec<String>,
    },
    ChildExited {
        status: std::process::ExitStatus,
        events: Vec<HelperEvent>,
        unparsed: Vec<String>,
    },
}

impl std::fmt::Display for WaitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "i/o error reading helper stdout: {e}"),
            Self::Deadline { events, unparsed } => write!(
                f,
                "deadline expired waiting for helper event predicate; \
                 events so far = {} (last 5: {:?}), unparsed lines = {:?}",
                events.len(),
                &events[events.len().saturating_sub(5)..],
                unparsed,
            ),
            Self::ChildExited {
                status,
                events,
                unparsed,
            } => write!(
                f,
                "helper exited before predicate matched: status = {status:?}; \
                 events so far = {} (last 5: {:?}), unparsed lines = {:?}",
                events.len(),
                &events[events.len().saturating_sub(5)..],
                unparsed,
            ),
        }
    }
}

impl std::error::Error for WaitError {}
