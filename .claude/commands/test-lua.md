---
description: Test Lua code changes with luacheck and functional tests
---

Test Lua code changes in Rspamd:

1. Run `luacheck src/plugins/lua/ lualib/ rules/` from project root
2. Report any issues found
3. If specific Lua files were modified, offer to run related functional tests
4. Check if test files need to be updated for the changes
5. Suggest creating new tests if adding new functionality

Provide clear feedback on what needs to be fixed.