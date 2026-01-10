---
description: Run all code quality checks (luacheck, clang-format check)
---

Run the following code quality checks for Rspamd project:

1. For Lua files: Run `luacheck src/plugins/lua/ lualib/ rules/` from project root
2. For C/C++ files: Check if clang-format would make changes (dry-run)
3. Report any issues found
4. Suggest fixes if there are problems

# Remove AI code slop

Check the diff against main, and remove all AI generated slop introduced in this branch.

This includes:
- Extra comments that a human wouldn't add or is inconsistent with the rest of the file
- Extra defensive checks or try/catch blocks that are abnormal for that area of the codebase (especially if called by trusted / validated codepaths)
- Casts to any to get around type issues
- Any other style that is inconsistent with the file

Report at the end with only a 1-3 sentence summary of what you changed

Focus on files that have been modified in the current git working directory.
