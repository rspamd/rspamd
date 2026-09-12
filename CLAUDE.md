## Non-Negotiable Rules

Breaking one of these causes an incident. Each has already cost us something —
the "Why this exists" lines are real events, not illustrations.

1. **Security first, always**
   Before any change, perform a full threat model: what new attack surface is
   introduced, what data flows in and out, what privileges are required, and
   what happens if this code is compromised or fed malicious input. If the
   change touches auth, crypto, network, file system, or user-controlled data,
   the threat model is written first. Specifically, and without exception:
   - **Never introduce or move secrets.** No hardcoded credentials, API keys,
     tokens or private keys. Never commit `.env` files, config carrying
     secrets, or debug logs that could contain them. A secret comes from the
     environment or a secret manager, and the code fails closed without it.
   - **All external input is hostile until proven otherwise.** Anything
     crossing a trust boundary — user input, API responses, file contents,
     query params, headers, rows from an untrusted source — is validated or
     typed before use. Prefer allow-lists over deny-lists. Never concatenate
     untrusted data into queries, commands, paths or HTML.
   - **Least privilege and explicit authorization.** Any new capability runs
     with the minimum privilege required. Authorization is checked explicitly
     and fails closed. Never assume the caller is authorized because they
     reached this code path.
   - **Prove the security properties still hold.** Confirm no new injection
     point, no secret in logs or errors, and no weakening of an existing
     control. If you cannot prove it is safe, do not ship it.

   > **Why this exists.** A `grep -rn` on a `.env` printed a live database
   > password into a transcript that cannot be un-leaked. Production database
   > dumps sat unencrypted in a home directory for two weeks. Deployed images
   > shipped the production IP and the full security architecture.

2. **Understand the full impact before changing anything**
   Map every place the change will touch or be affected by: callers, callees,
   data flows, tests, configs, deployments, docs, monitoring, and existing
   invariants. If you cannot clearly state what else is affected, do not
   proceed. A change is not done until it is verified running on the target —
   editing a file in a repository changes nothing on a server.

   > **Why this exists.** Twice a safeguard was recorded as installed on both
   > servers and existed on neither. Removing six variables from one `.env`
   > would have broken disaster recovery, because the init script asserts them
   > with `${VAR:?}` and aborts — discoverable only during a rebuild.

3. **Prove it works — and make sure the check could have failed**
   After the change, verify correctness and security with tests, manual checks,
   or both. Never mark a task done without evidence it behaves correctly under
   both normal and adversarial conditions. **A check that cannot report failure
   is worse than no check**, because it converts ignorance into confidence:
   prove it by making it fail once, or by including a known-positive control.
   When a measurement and your expectation disagree, suspect the instrument
   first.

   > **Why this exists.** A restore test "succeeded" having restored 0 files.
   > A capability check passed by parsing an empty list. A script rehearsal
   > passed because the corruption it should have caught cancelled itself out
   > in the test harness, and the same script then deleted 14 vault entries.

4. **Errors and warnings must reach someone who reads them**
   Every error path is deliberate. Never swallow an error silently. Prefer
   explicit error types or results over generic exceptions. Failures are
   logged with enough context to diagnose and without leaking sensitive data.
   Detection is not delivery: a warning that is generated and then dropped on
   the floor is indistinguishable from a check that never ran, so confirm it
   arrives on a channel someone actually reads.

   > **Why this exists.** The missing-database guard fired correctly on ~36
   > consecutive backup runs over 12 days and every one of them was delivered
   > as a green "Backup OK", because the warning reached only a channel that
   > was skipped whenever the other succeeded.

5. **Make the smallest change that leaves no rule half-applied**
   Prefer the minimal, reversible, simplest change that achieves the goal.
   Avoid drive-by refactors, speculative improvements, or expanding scope.
   Leave the codebase cleaner than you found it. But a rule stated in one
   place and not in its twin is not a smaller change — it is a broken one.

   > **Why this exists.** `.gitignore` was widened to `.env.*` and
   > `.dockerignore` was not; a later build copied two secrets backups into an
   > image. `.dockerignore` excluded `docs/` and never gained `*.md`, so the
   > two largest documents shipped from the repository root.

---

## Standards

Expected on every change and reviewable, but not tripwires.

6. **Plan first, then execute**
   For any non-trivial change, write a short plan covering the goal, the
   approach, the affected areas, and how you will verify it. Get agreement on
   the plan before writing code. Non-trivial means: more than one repository,
   anything on a production host, or anything a cheap rollback cannot undo.

7. **Match existing patterns and conventions**
   Follow the established style, architecture, naming, error-handling and
   testing patterns already present in the codebase. Do not invent new
   approaches unless the existing ones are clearly inadequate and you have
   justified the deviation.

8. **Handle errors explicitly and fail safely**
   Every error path is deliberate and every failure mode is chosen. Prefer
   failing closed to continuing in an unknown state.

9. **Keep the change readable and self-documenting**
   Code must be understandable by a future reader, including future you,
   without tribal knowledge. Prefer clear names, small functions and obvious
   control flow over cleverness. Comment the **why**, not the what, and only
   where it is non-obvious.

10. **Preserve testability, observability, and backwards compatibility**
    New code is easy to test in isolation; add or update tests for the change.
    Important behaviours produce useful logs or metrics so production problems
    can be diagnosed without guessing. Do not break existing callers, public
    APIs, data formats or configuration without an explicit migration plan —
    prefer additive, reversible changes, and document the migration path when
    a breaking change is unavoidable.

---

# Rspamd - Development Guide

## Build & Test

Use `/build-and-test` to build and run all unit tests. Manual steps:

- Build directory: `~/rspamd.build` (out-of-source, never build in source tree)
- Build: `cd ~/rspamd.build && ninja -j8 install`
- C/C++ tests: `~/rspamd.build/test/rspamd-test-cxx`
- Lua tests: `~/rspamd.build/test/rspamd-test -p /rspamd/lua`
- Lua lint: `luacheck src/plugins/lua/ lualib/ rules/` (from project root)

## Code Style

### C/C++ (tabs, 4-wide)
- Indentation: **tabs** (see `.clang-format`: `UseTab: ForContinuationAndIndentation`, `TabWidth: 4`)
- Run `clang-format` using the project `.clang-format` before committing
- Pointer alignment: right (`char *p`, not `char* p`)
- Braces: opening brace on same line for control statements, new line after functions

### Lua (2-space indent)
- Indentation: **2 spaces**, no tabs
- Run `luacheck` before committing any Lua changes

## Language Standards

### C++ (prefer for new code)
- Standard: **C++20** (`CMAKE_CXX_STANDARD 20`)
- Prefer C++ for all new code
- Use `contrib/ankerl/unordered_dense.h` for hash maps/sets — do **not** use `std::unordered_map` or `std::unordered_set`

### C (existing code)
- Keep plain C style in existing C files
- Use C++ only when writing new modules or substantially rewriting old ones

### Lua (LuaJIT + modern Lua compatibility)
- All Lua code must work with both **LuaJIT (5.1)** and **standard Lua 5.3, 5.4, and upcoming 5.5**
- Avoid Lua 5.2+ only features (goto, bitwise operators syntax, integer division `//`) unless guarded
- Use `bit` module or compat shims for bitwise operations
- Do not rely on LuaJIT-only FFI in core code paths unless a pure-Lua fallback exists

## Performance

- Focus on performance; use efficient algorithms and data structures
- Prefer `ankerl::unordered_dense` over std hash containers
- Minimize allocations in hot paths
- Profile before optimizing — measure, don't guess

## Printf Differences

Rspamd has its own printf implementation (`src/libutil/printf.h`) that differs from GNU printf. Key format specifiers:

| Format | Type | Notes |
|--------|------|-------|
| `%s` | `const char *` | null-terminated string |
| `%*s` | `int len, const char *` | length-prefixed string |
| `%v` | `GString *` | GLib string |
| `%V` | `rspamd_fstring_t *` | Rspamd fstring |
| `%T` | `rspamd_ftok_t` | Rspamd token |
| `%e` | `GError *` | GLib error |
| `%xs` | string | hex-encoded output |
| `%bs` | string | base32-encoded output |
| `%Bs` | string | base64-encoded output |
| `%z` | `ssize_t/size_t` | with optional `u`, `x`, `X`, `h`, `H` modifiers |
| `%d` | `int` | with optional `u`, `x`, `X`, `h`, `H`, `b`, `B` modifiers |
| `%l` | `long` | with optional modifiers |
| `%D` | `int32_t/uint32_t` | with optional modifiers |
| `%L` | `int64_t/uint64_t` | with optional modifiers |

**In Lua**: `rspamd_logger` uses `%s` as the universal placeholder for all argument types (not `%d`, `%f`, etc.).

Read `src/libutil/printf.h` before writing any C/C++ logging or formatting code.

## Commit Messages

Format: `[Tag] Description`

Tags: `[Feature]`, `[Fix]`, `[CritFix]`, `[Minor]`, `[Project]`, `[Rework]`, `[Conf]`, `[Test]`, `[Rules]`

All commits must be GPG-signed (`git commit -S`).

## Edit Tool - Whitespace Handling

The Read tool uses `→` to mark where line numbers end and file content begins.

**Rule:** Copy the EXACT whitespace that appears after the `→` marker.
- Whatever appears between `→` and the code text is what's actually in the file
- That whitespace must be used EXACTLY in Edit tool's old_string
- Don't count arrows, don't interpret - just copy what's after the `→`

**Example:**
14→		private byte tag;
For Edit, use: `		private byte tag;` (copy everything after →, including the two tabs)

**If Edit fails:** Stop and explain the problem. Do not attempt sed/awk/bash workarounds.

**IMPORTANT**: Trust the Read tool output. Copy what's after `→` into Edit immediately. DO NOT verify with sed/od/grep first - that's wasting time and the instructions already tell you to stop if Edit fails, not to pre-verify.
