# Rspamd Project Context

This document contains project-specific guidelines and requirements for the Rspamd mail processing system.

## Project Overview

Rspamd is a fast, free and open-source spam filtering system. The codebase consists of:
- **C/C++ code**: Core functionality in `src/`
- **Lua code**: Plugins, libraries, and rules in `src/plugins/lua/`, `lualib/`, `rules/`
- **Configuration**: UCL-based configuration in `conf/`
- **Tests**: Functional and unit tests in `test/`

## Code Style and Quality

### C and C++ Code

- **Formatting**: Always run `clang-format` using the `.clang-format` file in project root before every commit
- **Hash Maps**: DO NOT use C++ standard library hash maps (`std::unordered_map`, `std::hash`)
  - Always use containers from `contrib/ankerl/unordered_dense` for maps/sets and related hashes
- **Logging**: All debug logging functions use custom printf format implementation
  - Read comments in `src/libutil/printf.h` before adding logging code

### Lua Code

- **Linting**: Run `luacheck src/plugins/lua/ lualib/ rules/` before every commit
  - Change to project root directory before running luacheck
  - Resolve all warnings except those explicitly permitted by project exceptions
- **Logging**: `rspamd_logger` uses `%s` format strings for all argument placeholders

## Commit Message Format

All commits MUST follow structured format with tags:

### Commit Tags

- `[Feature]` - New features and capabilities
- `[Fix]` - Bug fixes and corrections
- `[CritFix]` - Critical bug fixes needing immediate attention
- `[Minor]` - Minor changes, tweaks, or version updates (prefer for whitespace, nil checks, etc.)
- `[Project]` - Project-wide changes, refactoring, or infrastructure
- `[Rework]` - Major reworking of existing functionality
- `[Conf]` - Configuration changes or updates
- `[Test]` - Test additions or modifications
- `[Rules]` - Changes to spam detection rules

### Examples

Single-line commits:
```
[Fix] Fix memory leak in dkim module
[Feature] Add support for encrypted maps
[Minor] Add missing cmath include
```

Multi-line commits (releases):
```
Release X.Y.Z

* [Feature] First feature description
* [Fix] First fix description
```

### GPG Signing

**ALL commits and tags MUST be GPG-signed:**
- Commits: `git commit -S`
- Tags: `git tag -s <tagname>`
- Verify: `git log --show-signature` or `git tag -v <tagname>`

## Pre-commit Checks

Pre-commit hooks verify:
- Trailing whitespace
- Line endings
- ClangFormat
- LuaCheck

Use `--no-verify` only when necessary and ensure code quality manually.

## Release Process

### 1. Update ChangeLog

Format:
```
X.Y.Z: DD MMM YYYY
  * [Feature] Feature description
  * [Fix] Fix description
```

Rules:
- Date format: `DD MMM YYYY` (e.g., `30 Sep 2025`)
- Each entry: `  * [Tag]` (two spaces, asterisk, space, tag)
- Group by tag type
- Keep descriptions concise

### 2. Create Release Commit

```bash
git add ChangeLog
git commit --no-verify -S -m "Release X.Y.Z

* [Feature] Feature 1
* [Fix] Fix 1
..."
```

### 3. Create Release Tag

```bash
git tag -s X.Y.Z -m "Rspamd X.Y.Z

Brief summary.

Main features:
* Feature 1

Critical fixes:
* Fix 1"
```

### 4. Update Version

After release, increment version in `CMakeLists.txt`:
```bash
git add CMakeLists.txt
git commit --no-verify -S -m "[Minor] Update version of rspamd to X.Y.Z"
```

## Version Numbers

Defined in `CMakeLists.txt`:
- **MAJOR**: Incompatible API changes
- **MINOR**: New features (backward-compatible)
- **PATCH**: Backward-compatible bug fixes

## Build System

### Build Directory
- Build directory: `~/rspamd.build` (separate from source tree)
- Use out-of-source builds with CMake + Ninja

### Build and Install
```bash
cd ~/rspamd.build
ninja -j8 install
```

### Testing

**Unit Tests (C/C++):**
```bash
test/rspamd-test-cxx
```

**Unit Tests (Lua):**
```bash
test/rspamd-test -p /rspamd/lua
```

**Functional Tests:**
- Run manually only (not automated in development workflow)
- Located in `test/functional/`

### Pre-commit Workflow
1. Make changes in source directory
2. Build: `cd ~/rspamd.build && ninja -j8 install`
3. Run unit tests:
   - C/C++: `test/rspamd-test-cxx`
   - Lua: `test/rspamd-test -p /rspamd/lua`
4. For Lua changes: `luacheck src/plugins/lua/ lualib/ rules/`
5. For C/C++ changes: Check `clang-format` compliance
6. Commit with GPG signature: `git commit -S -m "[Tag] Description"`

**Note**: Do NOT use `luac` for syntax checking - use the project's test suite instead.

## General Principles

- Write clear, descriptive commit messages
- One logical change per commit
- Reference issue numbers when applicable
- Keep commit history clean and meaningful
- Do not introduce changes conflicting with these rules
- When unsure, consult maintainers or in-code comments
