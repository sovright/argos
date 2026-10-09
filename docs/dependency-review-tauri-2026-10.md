# Tauri dependency review — October 2026

PR #248 updates Tauri to 2.11.6 but leaves 24 resolved crate versions without cargo-vet coverage. This record supports automated first-party source audits for the upgrade. It adds no exemptions; seven narrowly bounded publisher-trust entries were approved by the maintainer on 2026-10-09. Published archives were matched to the reviewed sources and the target Cargo.lock checksums. Existing accepted baselines and separately vetted transitive dependencies remain outside the delta reviews.

Platform limits matter: the reviews do not certify a tested mobile release, all supported FFI ABIs, or the disabled vendored D-Bus implementation. Re-review those paths before enabling them. Findings below distinguish executed tests from static assessment.

# tauri 2.10.3 -> 2.11.6 source review

Reviewer: OpenAI Codex (automated source review)
Date: 2026-10-09
Decision: safe-to-deploy delta audit is justified by the reviewed published-source changes. This is an automated source review, not a human audit, a full baseline audit, or a guarantee of absence of defects. Dependencies need independent cargo-vet coverage.

## Provenance and scope

Read the repository supply-chain/README.md and compared all changed files in the published crate archives. Downloaded both archives from https://static.crates.io/crates/tauri/tauri-VERSION.crate using curl with TLS verification. Verified every regular member (142 files per archive) byte-for-byte against the read-only shared source cache used for review. The SHA-256 archive digests are:

- 2.10.3: da77cc00fb9028caf5b5d4650f75e31f1ef3693459dfca7f7e506d1ecef0ba2d
- 2.11.6: 6fa5bacdb9bbad5954af3d1bd6cf6ae9192cab1b2e270f4a07f904610b9e85f4

Inspected the full Rust/Kotlin/build-script/permission/documentation delta, and the JavaScript bundle delta after introducing line breaks for readability. Parsed both bundled lockfiles to inspect package/source/dependency changes; all registry package sources remained crates.io. The bundled lockfile is not Argos's resolved dependency policy. The delta contains no new file and no removed file. No shared cargo-vet commands or cache mutations were performed.

## Security-relevant findings

1. **Remote IPC authorization is tightened** (`src/webview/mod.rs`, is_local_url/on_message). Windows/Android registered custom protocols now require the exact registered protocol prefix followed by `.localhost`, rather than accepting a matching first domain component from arbitrary hosts. Non-local custom application commands now require a resolved ACL even when the application lacks an app ACL manifest. The invoke-key check, local/remote capability resolution, and plugin authorization remain in place. Existing channel-fetch ACL special casing remains; the channel isolation fix below constrains its accessible entries. Tests for the origin changes were read, not run as part of a full Tauri build.

2. **Channel data is isolated by owning webview** (`src/ipc/channel.rs`, `src/manager/mod.rs`). Pending response bodies are indexed by the backend webview label and per-webview sequence, and fetch uses the injected calling Webview rather than a user-selected label. Wrapping IDs skip still-occupied entries. Closing a window/webview purges corresponding queues. This removes the prior globally addressable queue. A standalone check compiled the exact queue implementation with a minimal response-body stand-in: cross-webview rejection, owner-only one-shot fetch, per-webview ID sequences, u32 wraparound collision avoidance, and scoped purge all passed. This does not exercise native IPC, navigation lifetime, or label reuse during in-flight asynchronous responses.

3. **Protocol refactors preserve principal checks** (`src/ipc/protocol.rs`, `src/protocol/{asset,tauri}.rs`, `src/manager/{mod,webview}.rs`). Most IPC changes flatten control flow; isolation decryption and MIME fallback are retained. Asset serving switches Tokio file I/O inside synchronous block_on calls to synchronous std I/O, retaining SafePathBuf validation, scope authorization, range handling, and CORS response origin. Metadata length replaces seek-to-end. This does not solve pre-existing authorization/open TOCTOU or special-file behavior and was not treated as such. The tauri asset protocol now responds from an async task; configured response headers, CSP, resource hook, and error response remain. Development-only mobile proxying reuses a client and releases the response-cache lock before network reads, preserving the configured development destination/certificate behavior. No new outbound destination, wallet-file discovery, process execution, or secret collection appears in this delta. HTML data URL CSP injection moves to the tauri-utils html2 API; implementation of that dependency is outside this audit.

4. **Native menus retain explicit UI-thread ownership** (`src/menu/*`). Native menu handles move from Option storage plus a copied ID to ManuallyDrop storage. The sole destructor takes the handle once and schedules destruction on the main thread; the inner Clone implementation is removed while outer handles share Arc ownership. ID access now delegates to muda; inspected the resolved muda 0.19.3 id accessors in context to confirm they return immutable stored IDs, not RefCell/native UI accesses. Main-thread scheduling failure retains the existing shutdown/drop limitation; this audit does not claim to prove the runtime's thread-affinity guarantees. Other changes add Bring All to Front, fix the Windows-menu setter calling the Help-menu setter, and avoid unsupported macOS per-window menu operations.

5. **Permissions and API additions are bounded** (`build.rs`, generated references, JS bundle, window/webview/tray/app plugins). New default permissions expose multiple-window support, mobile activity/scene identifiers, and the combined tray icon/template setter. Window creation and setters remain outside defaults. Existing desktop command bodies are moved into shared platform modules for mobile multiwindow support. Native eval-with-callback is a Rust API forwarding to the runtime, not a new unguarded JS invoke command. General autofill configuration is an explicit API and does not promise to disable password/credit-card autofill. The generated JS delta consists of matching new wrappers/constants and minifier symbol renaming. Drag-region traversal now handles composed paths, explicit deep/false values, and interactive descendants; it still calls existing permission-checked window commands.

6. **Mobile and lifecycle changes** (`src/app.rs`, `src/plugin/mobile.rs`, window builders, Kotlin). Mobile window/activity/scene identity flows through managers/builders and runtime dispatch. Plugin callbacks release pending-call/channel locks before invoking callbacks. Android PluginManager becomes a process singleton and lifecycle delivery moves partly to a process observer; its TODO about retaining the first activity is a mobile lifecycle/reliability limitation, not an observed desktop secret exposure. Apple termination hooks only call supplied application callbacks. Native framework/runtime behavior is not independently certified here.

7. **Event changes** (`src/event/listener.rs`, `src/scope/fs.rs`). Once listeners unregister before callback invocation. Filesystem scope state is grouped in Arc and callback/listen/unlisten/emit work can be queued to avoid reentrant deadlocks; allow/deny path matching, separator/dotfile policy, and canonicalization logic do not change. The queue/atomic coordination was read, but no concurrency model checking was performed. In particular this is not a claim that all multi-thread event-ordering or callback-panic cases are correct. No application security boundary newly depends on those event delivery mechanics in the reviewed change.

8. **Build/manifest changes**. The build script delta only adds permission declarations. Inspected the full script for context: existing codegen/manifest output paths remain build-controlled; no new downloader or process launcher is added. Manifest updates select the related Tauri releases, muda/tray updates, default Linux dbus support, and html2 build features, plus iOS framework features. Those are dependency-selection changes, not certification of the selected packages.

## Validation and limitations

- Archive/member integrity comparison passed for both versions.
- Complete changed-file review plus structured bundled lockfile comparison completed.
- Exact extracted queue algorithm check passed (rustc, no Cargo or shared cache writes).
- No complete Tauri test suite, Argos GUI build, native Windows/Linux/mobile execution, fuzzing, or concurrency model checking was run by this reviewer. Parent workflow must report its own build/CI outcomes separately.
- The accepted 2.10.3 baseline, third-party dependency implementations (apart from targeted muda ID accessor context), platform frameworks, and application-specific capability/security configuration are not covered by this delta certification.
- No blocking malicious-code or introduced exploitable security finding was identified. API compatibility and native/mobile lifecycle reliability retain the limitations above; approval is a source-based delta assessment, not a blanket exemption.

## Changed-file inventory

- `Cargo.toml`
- `Cargo.lock`
- `build.rs`
- `.cargo_vcs_info.json`
- `Cargo.toml.orig`
- `scripts/bundle.global.js`
- `src/lib.rs`
- `src/app.rs`
- `src/async_runtime.rs`
- `permissions/app/autogenerated/reference.md`
- `permissions/tray/autogenerated/reference.md`
- `permissions/window/autogenerated/reference.md`
- `mobile/android-codegen/TauriActivity.kt`
- `mobile/android/src/main/java/app/tauri/plugin/PluginManager.kt`
- `mobile/android/src/main/java/app/tauri/plugin/Plugin.kt`
- `src/app/plugin.rs`
- `src/test/mock_runtime.rs`
- `src/test/mod.rs`
- `src/path/mod.rs`
- `src/resources/mod.rs`
- `src/webview/webview_window.rs`
- `src/webview/mod.rs`
- `src/webview/plugin.rs`
- `src/plugin/mobile.rs`
- `src/scope/fs.rs`
- `src/protocol/tauri.rs`
- `src/protocol/asset.rs`
- `src/tray/mod.rs`
- `src/tray/plugin.rs`
- `src/image/mod.rs`
- `src/manager/window.rs`
- `src/manager/mod.rs`
- `src/manager/webview.rs`
- `src/window/mod.rs`
- `src/window/plugin.rs`
- `src/menu/predefined.rs`
- `src/menu/normal.rs`
- `src/menu/check.rs`
- `src/menu/icon.rs`
- `src/menu/mod.rs`
- `src/menu/submenu.rs`
- `src/menu/plugin.rs`
- `src/menu/menu.rs`
- `src/ipc/channel.rs`
- `src/ipc/protocol.rs`
- `src/event/listener.rs`
- `src/window/scripts/drag.js`
- `src/menu/builders/menu.rs`


# PR 248 Tauri helper source review

Reviewer: OpenAI Codex (automated source review). Date: 2026-10-09.

Scope: tauri-build 2.5.6 -> 2.6.3; tauri-codegen 2.5.5 -> 2.6.3;
tauri-macros 2.5.5 -> 2.6.3; tauri-utils 2.8.3 -> 2.9.3.
The four safe-to-deploy delta entries are recorded in `supply-chain/audits.toml` under the repository review policy.

## Evidence and method

Compared all files in the eight published crate trees from
`/private/tmp/argos-pr248-vet-cache/src`. Read every executable source and manifest
delta, the entirety of new html2.rs, and surrounding HTML, macro dispatch,
CommandArg/scope-resolution and starting-binary code. Inventoried changed files
with recursive diff. Parsed each old/new Cargo.lock, inspected package additions
and source origins (crates.io registry or root package), rather than treating
lockfile checksum churn as source code. Dependencies are not certified by these
entries. There were no added executable/build-script files except utils html2.rs.

Byte-compared every regular file from all eight .crate archives to its extracted
source-tree counterpart: zero differences. All four target archive SHA-256 hashes
match PR Cargo.lock. Independently fetched all four base archives from
static.crates.io using curl with normal TLS verification and confirmed byte equality.
An initial Python urllib fetch failed local CA verification; no verification was
disabled, and curl succeeded. These are static source reviews, with no builds,
upstream tests, macro-expansion tests, browser CSP tests or platform execution.

## Findings and disposition

No malicious addition, new secret-reading path, unexpected network destination,
or demonstrated authorization bypass found in the reviewed deltas.

- **Build:** Windows RC append and version metadata are explicit build-author APIs.
  Android intent generation uses configured extensions/MIME strings and writes only
  the environment-selected project's AndroidManifest.xml. Those values are not XML
  escaped. Treat configuration as trusted developer input; this API must not be
  advertised as accepting untrusted MIME/extensions. An unmatched generated-block
  marker can remove trailing XML, a build/configuration integrity issue. Default
  Android associations include SEND, SEND_MULTIPLE and VIEW; application handlers
  must still treat incoming files as untrusted. Windows and Android not executed.
- **Codegen/HTML:** New html2 ports nonce policy and CSP insertion to dom_query.
  Script/style modification gates, existing nonce preservation, normalization and
  SHA-256/base64 hashes remain. Isolation inlining still permits traversal relative
  to trusted build assets, an explicitly pre-existing assumption. New inline code
  replaces script text rather than appending to old children. Parser/serializer
  equivalence for malformed/foreign HTML was not experimentally established.
- **Macros:** Command rename is explicit developer-controlled syntax. Generated
  handler patterns use the selected literal; arguments retain resolved ACL.
  `wrapper.rs` uses `stringify!(#r)` for renamed CommandItem.name, producing quoted
  names. Built-in consumers use this for diagnostics; CommandScope resolves from
  `command.acl` and GlobalScope from plugin identity. No bypass was found.
  `filter_unused_commands` continues matching Rust identifiers rather than rename
  literals, so the optimization may discard a renamed permitted handler (availability
  issue, not a grant). Argos source search found no renamed tauri commands.
- **Utils ACL:** Integer-first JSON number conversion fixes normal integer typing,
  but u64 values above i64::MAX cast to negative i64; e.g. u64::MAX becomes -1.
  This could misrepresent a custom numeric scope supplied by an application.
  The inspected Argos `gui/src-tauri/capabilities/default.json` only lists
  `core:default`, with no numeric scope objects. No untrusted permission-loading
  path or concrete bypass established. This edge case is retained in audit notes.
- **Utils remainder:** Added plist association construction uses typed plist values;
  configuration defaults and token generation align. Resource iteration resets
  stale state, handles empty directories and preserves filenames for empty targets.
  Empty-directory recursion remains bounded by trusted configured resource count.
  Startup constructor adds an unsafe block for ctor API adaptation but keeps
  current_exe/canonicalization and macOS symlink checks. The new Windows general
  autofill setting defaults true; consumers/default platform behavior require the
  separate runtime review. No password/credit-card disable claim is made.

The four delta entries are justified as source reviews under normal trusted-build
configuration assumptions. They do not constitute a full baseline audit, platform
validation, transitive review or human sign-off. In particular, dom_query/HTML stack,
ctor 0.8 and its helpers, phf 0.13 and plist need independent cargo-vet coverage.

## Archive SHA-256

| Crate | Base | Target |
|---|---|---|
| tauri-build | 4bbc990d1dbf57a8e1c7fa2327f2a614d8b757805603c1b9ba5c81bade09fd4d | bc9ce40b16101cb6ea63d3e221567affd1c3a9205f95d7bc574941a10636b632 |
| tauri-codegen | d4a24476afd977c5d5d169f72425868613d82747916dd29e0a357c84c4bd6d29 | 08279169ff42f8fc45a1dbc9dcae888893ba95288142e5880c59b93a26d2cfc5 |
| tauri-macros | d39b349a98dadaffebb73f0a40dcd1f23c999211e5a2e744403db384d0c33de7 | e8b394794f399a421811d06966343e7933fcae92d59f5180b9388d1174497a45 |
| tauri-utils | 219a1f983a2af3653f75b5747f76733b0da7ff03069c7a41901a5eb3ace4557d | 3e176a18e67764923c4f1ce66f25ae4abe5f688384d5eb1a0fa6c77f3d90f887 |


# PR248 window stack source review

Reviewer: OpenAI Codex (automated source review). Reviewed 2026-10-09 under supply-chain/README.md. The four safe-to-deploy delta records are recorded in `supply-chain/audits.toml`.

## Evidence and scope

Read every changed source hunk in the published tao 0.34.8 -> 0.35.3, wry 0.54.4 -> 0.55.1, tauri-runtime 2.10.1 -> 2.11.3, and tauri-runtime-wry 2.10.1 -> 2.11.4 archives, including mobile code. Inspected both original and normalized manifests, VCS metadata, docs/examples/changelog changes, and existing build scripts. Bundled Cargo.lock files were parsed to inventory every changed package/version and all source registries; their transitive source code is outside these four delta audits. All lock registries remain crates.io.

Fresh HTTPS downloads from static.crates.io byte-match the cached archives and every extracted file; target archive SHA256 matches the PR Cargo.lock. Integrity details follow below. Python HTTPS initially lacked its local CA bundle; curl succeeded with normal certificate verification (no insecure flag). No dependency code was executed and no native platform tests were run.

## Assessment

No introduced secret exfiltration, unexpected process execution, malicious package payload or severe security regression identified in these deltas. Desktop IPC authorization is not broadened. Android IPC/nav/custom-protocol callbacks are now indexed by native-supplied webview IDs, not IDs supplied inside JS message bodies. Windows popup handling now schedules on the owning HWND thread and completes the WebView2 deferral there; it removes the prior explicitly unsafe cross-thread COM wrapper. Linux D-Bus operations read/listen to local appearance metadata. iOS scene requests remain native APIs and URL events are parsed into url::Url rather than executed.

The safe-to-deploy assessment is source based, not a claim of cross-platform runtime correctness. Existing platform FFI assumptions and package dependencies remain relevant. The app's integration tests/build matrix must still run separately.

## Non-blocking observations and limitations

- tao src/platform_impl/android/ndk_glue.rs:82: five-argument android_binding macro forwards undefined $setup after its formal was renamed $on_activity_create. This appears to break that optional macro form at compile time; the explicit six-argument form does not use that arm. Not runtime exploitation and not a desktop blocker.
- wry src/android/main_pipe.rs:116-125: get_webview uses unwrap for an activity removed on destroy. A queued operation after OnDestroy can plausibly panic rather than return no webview. This is a mobile lifecycle robustness risk, not demonstrated by execution here. No deployment claim for a tested mobile lifecycle is made.
- tao Android raw-handle/context handling retains pre-existing JNI unsafe patterns. New per-activity maps and cleanup were inspected, but recreation/destruction races were not stress-tested. Several Android operations still unwrap native calls; native touch input routing is commented out by this delta. Do not infer mobile feature completeness from cargo-vet coverage.
- tao Linux portal SettingChanged match filters namespace/key but not the signal sender; a same-session peer may spoof theme metadata. Its effect is changing theme, not code execution or access to secrets. The initial theme lookup now favors portal settings over explicit window preference; this can be a UI regression. Theme reads have a five-second timeout.
- tauri-runtime-wry Apple content-process termination now reloads by default when no handler is supplied. This can reset unsaved UI state; it is not a guarantee of recovery-flow continuity after WebKit termination.
- General autofill is now configurable on Windows. Default true matches pre-existing Wry behavior and controls general form autofill, not passwords/cards.
- tao/wry VCS metadata has dirty=true in both old and new releases. The reviewed object is the published archive, not a claim that an upstream Git checkout reproduces the archive.

## Integrity

tao-0.34.8 sha256=9103edf55f2da3c82aea4c7fab7c4241032bfeea0e71fa557d98e00e7ce7cc20 files=117 cached archive and all source bytes match; PR lock checksum=False
tao-0.35.3 sha256=d1c93047acf68669466a34690ac58cca7010bd1b201e1ec86f1fd0a75d3dd4a9 files=119 cached archive and all source bytes match; PR lock checksum=True
wry-0.54.4 sha256=e5a8135d8676225e5744de000d4dff5a082501bf7db6a1c1495034f8c314edbc files=80 cached archive and all source bytes match; PR lock checksum=False
wry-0.55.1 sha256=186f9871daa55fd9c016578b810d149de58367113db7fb72b462d2323ce19514 files=81 cached archive and all source bytes match; PR lock checksum=True
tauri-runtime-2.10.1 sha256=2826d79a3297ed08cd6ea7f412644ef58e32969504bc4fbd8d7dbeabc4445ea2 files=13 cached archive and all source bytes match; PR lock checksum=False
tauri-runtime-2.11.3 sha256=b0b4bc95aed361b0019067d189a1174a603d460d0f6c72606512d59fc9c12ec8 files=13 cached archive and all source bytes match; PR lock checksum=True
tauri-runtime-wry-2.10.1 sha256=e11ea2e6f801d275fdd890d6c9603736012742a1c33b96d0db788c9cdebf7f9e files=22 cached archive and all source bytes match; PR lock checksum=False
tauri-runtime-wry-2.11.4 sha256=4e6fac707727b7a2f48e4ded90976324267371073edbb415ffb73bb0458d203f files=22 cached archive and all source bytes match; PR lock checksum=True


# PR248 ctor/dtor published-source review

Reviewer: OpenAI Codex (automated source review). Date: 2026-10-09.

Recommendation: record safe-to-deploy ctor 0.2.9 -> 0.8.0 delta and full audits for ctor-proc-macro 0.0.7, dtor 0.3.0, dtor-proc-macro 0.0.6. No blocking finding. This is an automated source review, not a human certification or formal proof.

## Source identity and coverage

Read-only input: /private/tmp/argos-pr248-vet-cache/{src,cache}. Every archive file member was compared byte-for-byte with its extracted counterpart. New package SHA-256 values matched PR248 Cargo.lock:

- ctor 0.8.0: 352d39c2f7bef1d6ad73db6f5160efcaed66d94ef8c6c573a8410c00bf909a98
- ctor-proc-macro 0.0.7: 52560adf09603e58c9a7ee1fe1dcb95a16927b17c127f0ac02d6e768a0e25bc1
- dtor 0.3.0: f1057d6c64987086ff8ed0fd3fbf377a6b7d205cc7715868cd401705f715cbe4
- dtor-proc-macro 0.0.6: f678cf4a922c215c63e0de95eb1ff08a958a81d47e485cf9da1e27bf6305cfa5
- ctor baseline 0.2.9: 32a2785755761f3ddc1492979ce1e48d2c00d09311c39e4466429188f3dd6501

Read every Rust source and example in all five published packages, complete normalized/original manifests and READMEs, plus all four new lockfiles. Both new 642-line src/macros/mod.rs copies are byte-identical. Scope covers the entire implementation, not only search hits. Baseline source contained 413 lines in src/lib.rs; new implementations comprise the macro engine, ctor exports (251 lines), dtor exports (81 lines), and token adapters (111 and 116 lines). No build scripts or bundled native payloads exist.

## Security-relevant changes

- The old syn/quote implementation becomes a dependency-free declarative parser with tiny optional proc-macro adapters. Both adapters only inspect caller tokens and generate support-macro invocations. No compile-time network, filesystem, subprocess, environment or credential access.
- Static initialization replaces unsafe mutable Option storage with std::sync::OnceLock and get_or_init. This enforces thread-safety bounds and prevents reading an uninitialized Option. Initializers still run eagerly via startup section callbacks and can initialize lazily if first accessed before their own callback.
- Parser accepts named/anonymous functions, visibility, static initialization, crate_path, custom linker sections, used(linker), and priorities; invalid attributes produce compile errors. Input is trusted source syntax, not runtime external data. Proc macro crate_path forwarding preserves that boundary.
- Startup callbacks use target-specific ELF .init_array, Apple __DATA,__mod_init_func,mod_init_funcs, Windows .CRT$XCU, and Xtensa/Cygwin .ctors sections. Windows callback returns zero usize; others return unit. WASM function callbacks use an atomic once guard. Unsupported targets fail at compile time.
- dtor registers callbacks through atexit or Apple's __cxa_atexit and DSO handle. This mechanism and discarded registration status already existed in baseline. No added teardown activity other than caller body execution.
- Attributes remain caller-controlled; arbitrary custom sections can break startup execution. Constructors and destructors run outside normal Rust main lifecycle, requiring suitable callback bodies. Those documented constraints are inherent in this crate's role.

## Nonblocking observations and limits

Warning feature names are inconsistent: function expansion checks __warn_on_missing_unsafe, while feature unification handles __no_warn_on_missing_unsafe; static expansion warns when the latter is present. This affects diagnostics, not generated callback body behavior. README minimum-Rust-version language does not reflect OnceLock's later stabilization. Neither affects the current toolchain smoke result.

Constructor ordering is not generally guaranteed; recursive or cyclic OnceLock initializers can deadlock. Destructor registration return codes are ignored, and dynamic unload semantics depend on the platform. These are not evidence of malicious code and were not newly introduced secret-handling paths. No claim of exhaustive UB absence or correctness for all supported target/linker combinations is made.

Tauri-utils 2.9.3's src/platform/starting_binary.rs uses the static constructor form for cached executable-path discovery. Reviewed this call site for integration context, but this audit does not certify the rest of Tauri-utils.

## Executed validation

Fixture /private/tmp/pr248-ctor-smoke uses path dependencies and patches pointing to reviewed sources, leaving the shared source/cache unchanged. Ran cargo run --offline --manifest-path /private/tmp/pr248-ctor-smoke/Cargo.toml using rustc 1.96.1 on native arm64 macOS. Exit 0, output:

    startup-static-ok
    dtor
    ctor-dtor

The fixture asserts two procedural/declarative constructor callbacks ran before main and checks OnceLock-backed static value 43. Its teardown callbacks use libc write and confirm direct dtor plus ctor's dtor re-export execute. No Windows, Linux, WASM, nightly used(linker), custom-section/priority, dynamic-unload or cross-version/MSRV runtime tests were run. Safe-to-deploy judgment rests on full source inspection plus this bounded smoke check, not on claiming a full platform test matrix.


## libdbus-sys 0.2.7

Reviewed the complete Rust FFI declarations, normalized/original manifests, default build script and optional vendored build helper. The archive SHA256 is `328c4789d42200f1eeec05bd86c9c13c7f091d2ba9a6ea35acdf51f31bc0f043`, matching Cargo.lock; all extracted files match that archive.

`cargo tree -i libdbus-sys --target all --all-features -e features --locked` shows only default/pkg-config features. The active build script probes system `dbus-1 >= 1.6`, with no downloads, source modification, or secret access. Runtime code consists of C ABI types, constants, callbacks and unsafe extern declarations. Checked object/error/iterator layouts against the shipped D-Bus headers, including explicit iterator padding for 64-bit copying. Ownership and pointer validity remain callers' obligations.

Review limitation: the bundled D-Bus 1.14.4 C implementation was not audited and is not compiled in the Argos feature graph. Enabling `vendored`, adding 32-bit Linux targets, or directly using additional FFI APIs requires renewed review. The optional helper writes generated headers under OUT_DIR and invokes the C compiler; its git-submodule fallback is disabled in this graph and unnecessary for the published archive. System-library patching remains the distribution's responsibility.

No safe-to-deploy audit is recorded for this crate. The maintainer approved bounded publisher trust on 2026-10-09; this does not resolve the ABI findings. FFI findings: some declarations use Rust bool for C dbus_bool_t; get_fixed_array declares a u32 return where C declares void, and free_string_array uses c_void. These are upstream ABI signature mismatches; ignoring a return value does not establish ABI correctness. The dbus wrapper ignores get_fixed_array's return; this review does not assert general ABI correctness on all architectures. No Linux runtime test was executed locally.



## Menu, tray, and PNG published-crate delta review

Reviewer: OpenAI Codex (automated source review). Reviewed the registry artifacts,
not just release notes. All six downloaded archive SHA-256 digests matched the
project lockfile where present or the crates.io sparse index for baseline versions.
No shared repository or cargo-vet cache was modified by this reviewer.

- **muda 0.17.1 -> 0.19.3:** Reviewed all runtime source deltas and manifest changes,
  including logical `KeyAccelerator` parsing/hash/mapping and backwards conversion,
  Windows `VkKeyScanW` fallback, native menu event dispatch and undo/redo commands,
  Windows subclass removal before handle/menu destruction, dynamic initialized
  `GetMenuItemInfoW` label buffers, GTK image insertion/removal, and macOS delegate
  retention and checked downcast. BSD support extends the existing GTK backend.
  No new build script, networking, subprocess spawning, or secret-data access found.
  Existing native FFI remains; source inspection is not a memory-safety proof.
  `cargo test --locked --lib accelerator`: **7 passed**, 5 unrelated tests filtered,
  on macOS. Non-ASCII Windows accelerator mapping was not exercised on Windows;
  the fallback returns `VkKeyScanW` directly and is a compatibility risk (the API's
  high-byte shift state is not unpacked), not evidence of supply-chain compromise.
- **tray-icon 0.21.3 -> 0.24.2:** Reviewed every runtime source delta and manifests.
  Right-click controls preserve their previous default; added `show_menu` uses the
  existing native menu handle. Windows notification structures now initialize
  `cbSize`, icon visibility uses `NIS_HIDDEN` and survives taskbar recreation, and
  menu activation moves to mouse-up followed by `WM_NULL`. macOS changes avoid
  unnecessary clones without storing new borrowed lifetimes. Existing GTK icon
  file writes/removal and runtime-directory selection are unchanged. No new
  network/secret/process behavior or build script found. `cargo check --locked
  --lib` passed on macOS using the package's published lockfile (muda 0.19.1 and
  png 0.18.0 in that isolated check, not the project's final resolved versions).
- **png 0.18.0-rc -> 0.18.1:** The Google upstream audit collection has Lukasz
  Anforowicz's `0.17.16 -> 0.18.0-rc` delta; refreshing imports supplies the baseline.
  Reviewed decoder chunk states and length bounds, CRC-before-metadata commitment,
  unknown critical chunk rejection, ancillary skip/reject states, APNG IDAT/fdAT
  ordering/default-frame validation/frame-count bounds; reviewed checked output
  sizing and the decompression lookback/available/filled regions, bounded frame
  output and scratch-buffer handling for partial rows. Reviewed Adam7 integer
  geometry and sparse/splat writes, streaming compressor finalization, adaptive
  and entropy filter selection, and scalar plus optional SIMD Paeth modules moved
  out of `filter.rs`. All writes remain safe Rust slices; `forbid(unsafe_code)` is
  retained. No new build script, network, subprocess or secret access found.
  Initial `cargo test --locked --lib` on the published crate: **75 passed, 8 failed
  because excluded image fixture files were absent, 1 ignored**. Tests were run
  with a private Cargo home/target directory after the first attempt could not
  write the default Cargo registry under sandbox restrictions. A second run after
  restoring the excluded `tests/` tree from exact published VCS commit
  `2a3f980245e3ae38b82ade96533e7b450e8477bb` completed with **83 passed, 0 failed,
  1 ignored** (16.91 seconds); library source was unchanged.

Automated source review supports the three `safe-to-deploy` delta records. It does
not replace full human security review, baseline review, transitive dependency
review, fuzzing, OS integration tests, or verification of all denial-of-service
behavior for attacker-controlled image sizes. Native Windows/Linux/BSD changes
were not executed, and nightly SIMD code was source-reviewed but not compiled.
No security blocker identified within this delta scope.

Artifacts reviewed were downloaded from `https://static.crates.io/crates/`.
Google baseline source: https://raw.githubusercontent.com/google/supply-chain/main/audits.toml

# objc2 framework 0.3.2 source review for PR #248

Reviewer: OpenAI Codex (automated source review). Date: 2026-10-09.

## Result and coverage boundary

The six crates below have sufficient source evidence for a **safe-to-run** assessment, not an unrestricted **safe-to-deploy** certification. No first-party deployment audit is recorded for these crates; the maintainer separately approved publisher trust as documented below. This assessment does not satisfy the project's default deployment criterion.

The cargo-vet [built-in definition](https://mozilla.github.io/cargo-vet/built-in-criteria.html) permits review discretion, but its deployment claim concerns reasonable uses of the crate generally. A note limiting an ordinary safe-to-deploy record to an application that never compiles the crate would overstate what was established here. Platform inactivity should instead be represented by explicit supported-target policy, if authorized, or the missing deployment review should remain visible. This is a review scope gap, not discovery of malicious code or a known vulnerability.

## Identity and source provenance

Each published archive was independently downloaded over TLS from `static.crates.io`, SHA-256 checked against the PR checkout's `Cargo.lock`, and extracted separately in `/private/tmp/pr248-objc-source`. Crate manifests identify objc2 commit `7b1abfd750a2cacaea71d6a56ecfb83cb7de560b`. Every packaged `src/` file, original manifest, translation config, and available Cargo.modified.toml was compared to upstream. Handwritten/config files match that commit. The generated directory is a Git submodule: the [pinned tree](https://github.com/madsmtm/objc2/tree/7b1abfd750a2cacaea71d6a56ecfb83cb7de560b) points to [objc2-generated commit 4c2d6fb86d17ed4b4b7e68e80994788b60521987](https://github.com/madsmtm/objc2-generated/tree/4c2d6fb86d17ed4b4b7e68e80994788b60521987). All **201 generated Rust files** match that pinned submodule byte-for-byte. This verifies published source provenance; it is not an independent regeneration from Apple SDK headers.

## Source observations

All six are normal Rust libraries with `build = false`, no build dependencies, no procedural macro entrypoints, and no executable targets. Manifests reference expected objc2/Foundation/framework, block, bitflags, dispatch or libc dependencies. Every crate links only its named Apple framework. Crate entrypoints only declare modules and reexports. Source-wide structural searches found no process launch, standalone network/filesystem implementation, embedded executable, environment-reading macro, inline assembly, global constructor, mutable static, custom linker-section hook, or dynamic-loading machinery. Dependencies' macro implementations are outside this review and require their own coverage.

The complete handwritten Rust entrypoints, CoreLocation `location.rs`, and CoreText `thread_safety.rs` were read. CoreLocation declares the inlined location types/constants and native methods; its three local executable functions simply invoke coordinate creation/validation C functions, with BOOL conversion as appropriate. Its coordinate representation is two C doubles. Its APIs are unsafe where platform contracts need caller verification. CoreText's handwritten file only contains test-gated assertions that toll-free bridged types lack Send/Sync. CoreData's only integration test constructs a fetch request and performs an unsafe generic view cast; no fetch, persistence, or filesystem action occurs.

Generated code was structurally inventoried and representative bindings/ownership handling inspected, **not read line-by-line as a full ABI and safety audit**:

- CloudKit: no local Rust function bodies; declarations, constants, objc2 class/protocol/method macros. Public methods are unsafe. Cloud access occurs only when a caller explicitly invokes the advertised native API.
- CoreData: four local function bodies perform pointer casts between generic Objective-C views, each exposed through an unsafe `cast_unchecked` API. Other methods are declarations/macros. Persistent store actions require explicit native API calls.
- CoreImage: no local Rust function bodies; framework declarations and macros, including many filter protocols. Public methods are unsafe.
- CoreLocation: generated declarations plus the handwritten wrappers described above. Platform location operations require callers to invoke their APIs.
- CoreText: a source-wide function-body extraction found 267 bodies reducing to six patterns: native FFI call, optional/required retained-object construction from Create/Copy returns, optional/required retain of Get returns, or non-null assertion. No additional algorithm, buffer copy, external process, hidden I/O, or initializer appears in those bodies. NULL-required returns panic instead of constructing a null retained handle. Native font APIs, callback lifetimes, pointer/length contracts, all struct layouts/encodings, and all safety declarations were **not independently checked against the SDK**.
- UserNotifications: generated method declarations and three DefaultRetained bodies forwarding to new(). Unlike most of these frameworks, it exposes many safe methods based on translator configuration declaring documentation reviewed. That upstream assertion was inspected but not accepted as independent proof of all method safety. Notification scheduling/removal and permission requests are explicit API operations, not crate-load/build behavior.

No build or runtime test was executed as part of this review. Normal compiling/testing has no identified surprising ambient behavior. This safe-to-run finding does not promise arbitrary calls to framework APIs are side-effect free: those APIs intentionally provide cloud, persistence, font, location and notification capabilities.

## Current Argos target exposure

Read-only `cargo tree --locked --offline --target TARGET -i CRATE@0.3.2` succeeded for each of six crates on each target below. All six are absent for `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-unknown-linux-gnu`, and `x86_64-pc-windows-msvc`. All six are present for `aarch64-apple-ios` through objc2-ui-kit and the Tauri/tao/wry dependency graph. Exact outputs are in `/private/tmp/pr248-objc-source/target-exposure.json`.

Therefore the current default desktop graph introduces no executed build/runtime code from these six packages. This statement is tied to the reviewed checkout, targets, and default feature graph, not all possible feature combinations or future releases. Mobile deployment, new features, or new reverse dependencies require re-evaluation. Full safe-to-deploy coverage still requires enough platform-contract review to reason about the generated unsafe declarations/macros and CoreText ownership/callback/ABI contracts, or a reputable existing deployment audit.

## Archive checksums

- `objc2-cloud-kit 0.3.2`: `73ad74d880bb43877038da939b7427bba67e9dd42004a18b809ba7d87cee241c`; 54 generated files; 13579 packaged Rust lines.

- `objc2-core-data 0.3.2`: `0b402a653efbb5e82ce4df10683b6b28027616a2715e90009947d50b8dd298fa`; 56 generated files; 9360 packaged Rust lines.

- `objc2-core-image 0.3.2`: `e5d563b38d2b97209f8e861173de434bd0214cf020e3423a52624cd1d989f006`; 25 generated files; 20048 packaged Rust lines.

- `objc2-core-location 0.3.2`: `ca347214e24bc973fc025fd0d36ebb179ff30536ed1f80252706db19ee452009`; 28 generated files; 3875 packaged Rust lines.

- `objc2-core-text 0.3.2`: `0cde0dfb48d25d2b4862161a4d5fcc0e3c24367869ad306b0c9ec0073bfed92d`; 21 generated files; 18871 packaged Rust lines.

- `objc2-user-notifications 0.3.2`: `9df9128cbbfef73cda168416ccf7f837b62737d748333bfe9ab71c245d76613e`; 17 generated files; 2402 packaged Rust lines.

## Publisher metadata (not an audit or trust decision)

Exact-version publisher records read from the parent cargo-vet session cache `/private/tmp/argos-pr248-vet-cache/crates-io-cache.json`. Direct crates.io API access returned HTTP 403, so these are cache-derived rather than independently refreshed. Identity alone does not close the deployment review gap.

- `objc2-cloud-kit 0.3.2`: `2025-10-04T15:48:20.595991Z`, `madsmtm` / `Mads Marquart`, user ID `36629`.

- `objc2-core-data 0.3.2`: `2025-10-04T16:14:39.575218Z`, `madsmtm` / `Mads Marquart`, user ID `36629`.

- `objc2-core-image 0.3.2`: `2025-10-04T16:15:14.504081Z`, `madsmtm` / `Mads Marquart`, user ID `36629`.

- `objc2-core-location 0.3.2`: `2025-10-04T15:48:12.323758Z`, `madsmtm` / `Mads Marquart`, user ID `36629`.

- `objc2-core-text 0.3.2`: `2025-10-04T16:15:20.614374Z`, `madsmtm` / `Mads Marquart`, user ID `36629`.

- `objc2-user-notifications 0.3.2`: `2025-10-04T16:15:39.439199Z`, `madsmtm` / `Mads Marquart`, user ID `36629`.

## Approved publisher trust

On 2026-10-09 the maintainer approved publisher `diwic` (crates.io ID 429) for libdbus-sys 0.2.7, bounded to 2025-12-11 through 2025-12-12, and `madsmtm` (ID 36629) for the six objc2 0.3.2 crates, bounded to 2025-10-04 through 2025-10-05. These historical publication windows do not authorize future releases. No new blanket exemptions are added. Publisher identity/date evidence is committed in imports.lock. This accepts upstream publisher responsibility rather than asserting a complete first-party ABI audit.
