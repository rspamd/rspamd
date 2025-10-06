# Claude Code Configuration for Rspamd

This directory contains Claude Code configuration and custom commands for the Rspamd project.

## Files

- **project_context.md** - Project-specific guidelines, code style, commit format, and release procedures
- **settings.local.json** - Local permissions and settings for Claude Code
- **commands/** - Custom slash commands for common Rspamd development tasks

## Available Commands

### Build and Test Commands

#### `/build`
Build and install Rspamd using the project's build system:
- Navigate to `~/rspamd.build`
- Run `ninja -j8 install`
- Report build status

#### `/test`
Run Rspamd unit tests:
- C/C++ tests: `test/rspamd-test-cxx`
- Lua tests: `test/rspamd-test -p /rspamd/lua`
- Report results

#### `/build-and-test`
Complete build and test workflow:
- Build with ninja
- Run all unit tests (C/C++ and Lua)
- Comprehensive status report

### Code Quality Commands

#### `/check-code`
Run all code quality checks (luacheck for Lua, clang-format check for C/C++).
Focuses on modified files in the current working directory.

#### `/format-code`
Format C/C++ code according to project style using clang-format.
For Lua files, suggests running luacheck but doesn't auto-fix.

#### `/test-lua`
Test Lua code changes:
- Run luacheck on all Lua code
- Suggest related functional tests to run
- Check if test updates are needed

### Git and Release Commands

#### `/prepare-commit`
Comprehensive pre-commit workflow:
- Format code (C/C++)
- Run luacheck (Lua)
- Build project
- Run unit tests
- Stage formatted files
- Suggest properly formatted commit message
- Remind about GPG signing

#### `/review-pr`
Review a GitHub pull request for compliance with Rspamd standards:
- Commit message format
- Code style compliance
- Test coverage
- Project-specific requirements

#### `/create-release`
Interactive guide through the Rspamd release process:
- Update ChangeLog
- Update version in CMakeLists.txt
- Create signed release commit
- Create signed release tag
- Update version for next dev cycle

## Project Rules

The configuration automatically enforces Rspamd project rules:

### C/C++ Code
- Must be formatted with clang-format before commit
- No `std::unordered_map` or `std::hash` - use `contrib/ankerl/unordered_dense` instead
- Custom printf format for logging (see `src/libutil/printf.h`)

### Lua Code
- Must pass luacheck before commit
- `rspamd_logger` uses `%s` for all argument placeholders

### Commit Messages
All commits must follow the format: `[Tag] Description`

Tags:
- `[Feature]` - New features
- `[Fix]` - Bug fixes
- `[CritFix]` - Critical fixes
- `[Minor]` - Minor changes (prefer for whitespace, nil checks, etc.)
- `[Project]` - Project-wide changes
- `[Rework]` - Major refactoring
- `[Conf]` - Configuration changes
- `[Test]` - Test changes
- `[Rules]` - Spam detection rule changes

### GPG Signing
**ALL commits and tags MUST be GPG-signed:**
```bash
git commit -S -m "[Tag] Description"
git tag -s X.Y.Z -m "Tag message"
```

## Usage

Commands are invoked with a forward slash in Claude Code:

```
/check-code
/prepare-commit
/review-pr 5655
```

Claude Code will automatically reference `project_context.md` for all interactions in this project.

## Permissions

The following commands are pre-approved and won't require confirmation:
- `gh pr view` / `gh pr diff` - View GitHub PRs
- `luacheck` - Lint Lua code
- `clang-format` - Format C/C++ code
- `ninja` - Build project
- `test/rspamd-test-cxx` - Run C/C++ unit tests
- `test/rspamd-test` - Run Lua unit tests

**Note**: `luac` is NOT used - Rspamd has its own test suite for syntax validation.

## Integration with Cursor Rules

The project also has `.cursor/rules/` directory with MDC files. The Claude Code configuration mirrors and extends those rules for compatibility.
