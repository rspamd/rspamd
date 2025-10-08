---
description: Format code according to project style (clang-format for C/C++)
---

Format code files according to Rspamd project style:

1. Identify modified C/C++ files in the current git working directory
2. Run `clang-format -i` on those files using the `.clang-format` config
3. Report what was formatted
4. For Lua files, suggest running luacheck but don't auto-fix

Make sure to use the `.clang-format` file in the project root.