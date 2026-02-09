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
