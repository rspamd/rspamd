# Project Memories

## Tools & Preferences

- **2026-01-09**: Use `gh` CLI to operate with GitHub API: getting PRs, issues, etc.

## Project Standards

- **2026-01-09**: Current year is 2026 - use this for copyright headers and date references.
- **2026-01-09**: Redis sync API is actually a coroutines API - it is unstable and fragile. Refrain from using it anywhere except in `rspamadm` utility.
- **2026-01-09**: When performing Lua `pcall` from C, use `rspamd_lua_traceback` as the message handler (errfunc) to preserve stack traces for debugging.
- **2026-01-09**: In Lua C API prefer using `lua_check_text_or_string` to accept both `rspamd{text}` userdata and Lua native strings (string interning is expensive in Lua).
