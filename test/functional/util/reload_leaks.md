# Reload leak checks

Build out of source with `-DSANITIZE=address,leak -DENABLE_JEMALLOC=OFF` and a
compiler/runtime that supports LeakSanitizer. Run from the build directory:

```sh
ctest -R '^reload-leaks-' --output-on-failure -j4
```

If LLVM's symbolizer is outside `PATH`, export it first:

```sh
export ASAN_OPTIONS=external_symbolizer_path=/path/to/llvm-symbolizer
```

The four CTests each perform eight actual changes against a real foreground
master, normal worker, controller, and Hyperscan helper. They use isolated config,
cache, log, and map files, local Unix sockets, and a loopback HTTP server. They
require no installed configuration or external services. Python 3 is required;
CTest registers them only in AddressSanitizer builds. The script returns 77 for
a binary without AddressSanitizer.

| Test | Change and observable result |
| --- | --- |
| `reload-leaks-config` | Rewrite a UCL value, send SIGHUP, observe the new value and replacement worker PIDs. |
| `reload-leaks-lua` | Rewrite Lua rule code with unchanged UCL, send SIGHUP, observe the new rule result and replacement PIDs. |
| `reload-leaks-maps` | Atomically replace five local map types, observe new values and removed old keys in the same workers. |
| `reload-leaks-http-maps` | Serve changed bodies and ETags, exercise 200/304/503 responses, observe new values and preservation after errors in the same workers. |

The map types are set, key-value, regexp, radix, and Lua callback. Both scanner
and controller results are checked, including the controller that fetches HTTP
maps and the scanner that reads their shared cache. Every third config/Lua
change also attempts a rejected reload and verifies the old behavior and PIDs.
The rejected Lua case opens a different log file before compilation fails;
rollback must restore the original default logger. Config unload hooks verify
that the master releases each superseded configuration. Logging also uses a
radix map to exercise references from configuration maps into logger storage.

## What passing means

Each test first runs an unchanged startup baseline, then its reload sequence.
After graceful shutdown it checks every process's native sanitizer report.
Allocation stacks are grouped by their first four allocation frames and process
role. No stack may gain bytes or objects relative to the largest same-role
startup report. Any AddressSanitizer memory safety error, unknown process role,
or incomplete leak report fails the check. Raw reports are retained.

This is a check for **additional reload leaks**, not a claim that daemon startup
is entirely leak-free. The current macOS runtime reports native system-library
startup allocations and scanner resolver allocations even without reloading.
Those remain visible in the baseline. One inherited alternate signal stack per
child, allocated by the initial `rspamd_set_crash_handler` call, is reported
separately: ASan can replace the active stack after fork, making this startup
allocation appear inconsistently. Multiple stacks, a master stack leak, or a
stack allocated during reread are not exempted. No LSan suppressions are used.

After two warmup generations, fixed-size fixtures must stay within 32 KiB of
pool storage variation. This catches reachable logger/error-buffer retention
that LSan cannot detect. Pool measurement sums the per-callsite live-byte counters using optional
LuaJIT FFI and is marked unavailable on other Lua runtimes. The aggregate
`bytes_allocated` counter retains freed chain-header accounting, so polling it
would incorrectly count scan requests as retained memory. In-place map tests also require the final Lua
heap after several settled full-GC scans to remain within 64 KiB of its lowest steady-state sample;
intermediate compilation/cache spikes are recorded without treating them as
permanent retention. These bounds are regression checks, not a long-duration
memory stress test or coverage of every plugin/backend.

Results are saved under `test/reload-leaks/<mode>/run-*/` in the build directory:
`summary.json`, baseline/changed per-PID `asan.*` reports, daemon logs, generated
fixtures, and HTTP request counters. Socket paths use a separate short temporary
directory to fit macOS `sockaddr_un` limits.

For a longer run or a separate output location:

```sh
python3 /path/to/source/test/functional/util/reload_leaks.py \
  --rspamd /path/to/build/src/rspamd --source /path/to/source \
  --mode http-maps --iterations 30 --output-dir /tmp/rspamd-reload-leaks
```

To verify the native leak detector itself, add `--inject-leak` with `--mode lua`
or `--mode config`. This diagnostic requires LuaJIT and deliberately loses one
12,345-byte allocation for every changed configuration. It **must fail** and
show additional master allocations. Do not use it in passing CI runs.

## Controller query ownership

`cases/222_controller_queries.robot` is a normal Robot functional suite. It
replaces the dedicated `rspamd-test-controller` binary and compiles no private
controller implementation into test code. Run it through the existing harness:

```sh
RSPAMD_TOPDIR=/path/to/source RSPAMD_INSTALLROOT=/path/to/install \
  python3 -m robot --suite '222*' /path/to/source/test/functional/cases
```

The five cases send 128 real TCP requests each: passwordless read/write access
with empty and populated queries, and the existing C `/fuzzydelhash` custom
command. No `secure_ip` is configured, so the tests exercise authentication
rather than trusted-loopback access. The read case checks `read_only`; the write
case checks that authentication reaches body validation. The custom case checks
percent-decoded, duplicate query arguments after their conversion to copied
headers, without contacting fuzzy storage.

These behavior assertions run on ordinary builds too. Under ASan/LSan, the
helper compares the query allocations against a warmed startup baseline. It
checks allocation stacks containing `rspamd_controller_check_password` or
`rspamd_controller_handle_custom`, so unrelated macOS startup allocation
variation cannot mask a controller regression. Symbolized stacks are required:
put `llvm-symbolizer` in `PATH` or set `external_symbolizer_path` as shown above.
All ASan memory safety errors still fail regardless of allocation origin.
Per-case configs, logs, raw sanitizer reports, and summaries remain under the
Robot output directory's `controller-queries/` subdirectory.
