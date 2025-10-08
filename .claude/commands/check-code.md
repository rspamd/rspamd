---
description: Run all code quality checks (luacheck, clang-format check)
---

Run the following code quality checks for Rspamd project:

1. For Lua files: Run `luacheck src/plugins/lua/ lualib/ rules/` from project root
2. For C/C++ files: Check if clang-format would make changes (dry-run)
3. Report any issues found
4. Suggest fixes if there are problems

Focus on files that have been modified in the current git working directory.
