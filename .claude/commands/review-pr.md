---
description: Review a GitHub PR for code quality and project standards
---

Review a GitHub pull request for Rspamd project compliance.

Given a PR number or URL:

1. Fetch PR details using `gh pr view <number>`
2. Check PR title follows commit message format ([Tag] description)
3. Review changed files for:
   - C/C++ files: clang-format compliance, no std::unordered_map usage
   - Lua files: luacheck compliance, proper rspamd_logger usage
   - Commit messages: proper tags and GPG signatures
4. Check if tests are included for new features
5. Provide detailed feedback on what needs to be fixed
6. Suggest improvements following project guidelines

Be thorough but constructive in the review.
