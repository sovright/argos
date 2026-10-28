# Dependency review: tokio 1.51.6 and tokio-macros 2.7.1 (October 2026)

Why: PR #292 moves tokio from 1.50.0 to 1.51.6 for
[RUSTSEC-2026-0386](https://rustsec.org/advisories/RUSTSEC-2026-0386) and holds
tokio-macros at 2.7.1. `cargo vet --locked` failed because neither version was
audited. Following `supply-chain/README.md`, this review records delta audits
instead of widening the exemptions. No exemption was added or moved; the
existing 1.50.0 / 2.6.1 exemptions remain the base of the delta.

Scope: the complete published crates.io source deltas from
`cargo vet diff --mode local`. All lines were read; nothing was sampled.

| Crate | Delta | Diff lines | Verdict |
| --- | --- | --- | --- |
| tokio | 1.50.0 -> 1.51.6 | 7,172 | safe-to-deploy |
| tokio-macros | 2.6.1 -> 2.7.1 | 366 | safe-to-deploy |

Reviewer: Claude (automated source review). Upstream tests, loom and miri were
not executed.

## The advisory

RUSTSEC-2026-0386: "`AsyncFd::new` and related constructors violate I/O
safety" (unsound, use-after-free). The patched ranges are `>=1.51.6, <1.52.0`
and `>=1.53.3`; 1.51.6 is the first patched release on the 1.51 LTS line.

- `src/io/async_fd.rs` (1.51.6): new `pub unsafe fn register` and
  `register_with_interest`, with a documented contract (the fd is valid, open
  and unchanged for the `AsyncFd`'s lifetime). The safe `new`, `with_interest`,
  `try_new` and `try_with_interest` are deprecated and now wrap the unsafe
  constructors. **They are still callable and still unsound if misused.** Argos
  source has no `AsyncFd` use; transitive users were not enumerated.
- `src/runtime/io/driver.rs` (1.51.5): `deregister_source` no longer releases
  the `ScheduledIo` when `EPOLL_CTL_DEL` fails, so a closed-but-duplicated fd
  leaks instead of leaving epoll with a dangling pointer. The old leak
  regression test is removed and a new duplicate-fd test is added.

## Supply-chain checks

- tokio stays `build = false` with no `links`. tokio-macros changes only its
  version in `Cargo.toml`.
- New manifest entries: an optional `libc` dependency under
  `cfg(target_os = "wasi")`, and the socket2 cfg widened to WASIp2. Both are
  inert on Argos targets.
- Raised minimums: mio 1.0.1 -> 1.2.0 and socket2 0.6.0 -> 0.6.3. Both were
  already resolved on main, so no resolved crate changes.
- `Cargo.lock` delta vs main: only the tokio and tokio-macros versions and
  checksums, plus the new workspace crate `argos-sprout-pack`.
- Added-line grep for env, `include_*`, `Command::new`, `read_dir`, sockets,
  URLs, base64, `extern "C"`, `#[link]` and `build.rs`:
  - URLs appear only in CHANGELOG and doc text.
  - Process, procfs and loopback socket use appears only in tests.
- No obfuscated code, encoded blobs, telemetry or new endpoints.
- tokio-macros does no I/O, env access or unsafe at expansion time.

## Functional changes (tokio)

- **sync:**
  - `RwLock` rejects `max_readers == 0`, where two writers could otherwise
    both hold the lock.
  - Semaphore bounds `num_permits` by `MAX_PERMITS`, keeps the CLOSED bit in
    `forget_permits`, and wakes waiters in batches outside the lock on
    `close()`.
  - mpsc fixes block reclamation on index wraparound and `len()` underflow;
    `Permit::send` forgets itself first; `recv_many` and `try_recv` edge cases
    are fixed.
- **Lock ordering:** wakers are woken or dropped outside locks in
  DuplexStream, broadcast, timers, JoinSet and the blocking pool.
- **Runtime:**
  - `Builder::name`, `Handle::name()` and `worker_index()` are new, and
    LocalRuntime is stabilized.
  - The current_thread driver gets a zero-timeout poll after `before_park`.
  - Timer wheels drain at shutdown.
  - io_uring (unstable) closes fds from cancelled `open` completions.
- **net:** UDP receive and peek now wait on `READABLE | ERROR`; WASIp2
  networking cfgs; Hurd `peer_cred`.
- **fs and process:** buffered relative seek uses `checked_add`; on Windows
  the child wait is unregistered before the process handle closes.
- **Macros** (`join!`, `try_join!`, `select!`): hygiene paths only.

## Unsafe code that changed

| Site | Judgment |
| --- | --- |
| `io/async_fd.rs` `register` / `register_with_interest` | Sound; documented caller contract (the fix) |
| `io/async_fd.rs` deprecated safe constructors wrapping `unsafe { register* }` | Unchanged behaviour; unsound if misused (advisory caveat) |
| `runtime/io/driver/uring.rs` `OwnedFd::from_raw_fd` on cancelled opens (3 sites) | Sound; a fresh fd owned by no one else. Unstable feature only |
| `sync/mpsc/list.rs` `is_maybe_closed` derefs | Sound; receiver-only, and only the receiver frees blocks |
| `sync/mpsc` removed `is_closed` derefs | Removal; less unsafe |
| `sync/batch_semaphore.rs` waker take in batched `close()`, `trace_assigned` | Sound; under the waiters lock |
| `macros/{join,try_join,select}.rs` `Pin::new_unchecked` | Re-pathed only; same pinning invariant |
| `net/tcp/socket.rs`, `net/udp.rs` `from_raw_fd(into_raw_fd())` | Unchanged; cfg widened for WASI |

## tokio-macros

A new `name = "<literal>"` attribute on `#[tokio::main]` and `#[tokio::test]`
emits `.name(..)` on the builder. The `tokio_unstable` guard for
`flavor = "local"` is removed. Everything else is error-message and
documentation text.
