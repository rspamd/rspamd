# Contributing to Rspamd

:tada: First off, thanks for taking the time to contribute! :tada:

The following is a set of guidelines for contributing to Rspamd and its packages, which are hosted in
the [Rspamd Organization](https://github.com/rspamd) on GitHub. These are mostly guidelines, not rules. Use your best
judgment, and feel free to propose changes to this document in a pull request. This contribution policy is heavily
inspired by [Atom editor](https://github.com/atom/atom).

#### Table Of Contents

[I don't want to read this whole thing, I just have a question](#i-dont-want-to-read-this-whole-thing-i-just-have-a-question)

[How Can I Contribute?](#how-can-i-contribute)

* [Reporting Bugs](#reporting-bugs)
* [Using AI Tools](#using-ai-tools)

[Styleguides](#styleguides)

* [Git Commit Messages](#git-commit-messages)
* [C and C++ style guide](#c-and-c-styleguide)
* [Lua style guide](#lua-styleguide)

## I don't want to read this whole thing I just have a question

> **Note:** Please don't file an issue to ask a question. You'll get faster results by using the resources below.

We have an official site with a detailed FAQ and various community support resources.

* [Support channels explained](https://rspamd.com/support.html)
* [Rspamd FAQ](https://rspamd.com/doc/faq.html)

The best way to ask a question and to get a relevant reply is the mailing list:

* [Join Rspamd mailing lists](https://lists.rspamd.com/)

If chat is more your speed, you can join the Rspamd developers and users using Telegram or IRC:

* [Join Rspamd telegram channel](http://t.me/rspamd)
* [Join Rspamd IRC channel](https://oftc.net/):
    * server: ircs://irc.oftc.net:6697
    * channel: #rspamd

Please bear in mind that even though telegram/irc are chat services, sometimes it takes several hours for community
members to respond &mdash; please be patient!

## How Can I Contribute?

### Reporting Bugs

This section guides you through submitting a bug report for Rspamd. Following these guidelines helps maintainers and the
community understand your report :pencil:, reproduce the behavior :computer: :computer:, and find related reports :
mag_right:.

When you are creating a bug report, please [include as many details as possible](#how-do-i-submit-a-good-bug-report).
Fill out the required template, the information it asks for helps us resolve issues faster.

> **Note:** If you find a **Closed** issue that seems like it is the same thing that you're experiencing, open a new
> issue and include a link to the original issue in the body of your new one.

#### Before Submitting A Bug Report

* Read about bug reporting in general: https://rspamd.com/doc/faq.html#how-to-report-bugs-found-in-rspamd
* Enable relevant debugging logs: https://rspamd.com/doc/faq.html#how-to-debug-some-module-in-rspamd
* Check the FAQs about Core files in case of fatal
  crash: https://rspamd.com/doc/faq.html#how-to-figure-out-why-rspamd-process-crashed
* Check that your issue isn't already filed: https://github.com/issues?utf8=%E2%9C%93&q=is%3Aissue+user%3Arspamd
* Check that there is not already an experimental package or master branch

#### How Do I Submit A (Good) Bug Report?

Explain the problem and include additional details to help maintainers reproduce the problem:

* **Use a clear and descriptive title** for the issue to identify the problem.
* **Describe the exact steps which reproduce the problem** in as many details as possible. For example, start by
  explaining how you started Rspamd, e.g. which custom configuration are you using, or what message have you scanned.
  When listing steps, **don't just say what you did, but explain how you did it**.
* **Provide specific examples to demonstrate the steps**. Include links to files or GitHub projects, or copy/pasteable
  snippets, which you use in those examples. If you're providing snippets in the issue,
  use [Markdown code blocks](https://help.github.com/articles/markdown-basics/#multiple-lines).
* **Describe the behavior you observed after following the steps** and point out what exactly is the problem with that
  behavior.
* **Explain which behavior you expected to see instead and why.**
* **If you're reporting that Rspamd crashed**, include a crash report with a stack trace from the operating
  system: https://rspamd.com/doc/faq.html#how-to-figure-out-why-rspamd-process-crashed
* **If the problem wasn't triggered by a specific action**, describe what you were doing before the problem happened and
  share more information using the guidelines below.

Provide more context by answering these questions:

* **Did the problem start happening recently** (e.g. after updating to a new version of Rspamd) or was this always a
  problem?
* If the problem started happening recently, **can you reproduce the problem in an older version of Rspamd?** What's the
  most recent version in which the problem doesn't happen? You can download older versions of Rspamd
  from [the releases page](https://github.com/rspamd/rspamd/releases).
* **Can you reliably reproduce the issue?** If not, provide details about how often the problem happens and under which
  conditions it normally happens.
* If the problem is related to scanning messages, **does the problem happen for all messages or only some?**

Include details about your configuration and environment:

* **Which version of Rspamd are you using?** Use `rspamd --version` to get the detailed information about the version
  and the compile flags used.
* **What's the name and version of the OS you're using**?
* **What hardware are you using, including CPU generation**, e.g. Intel Haswell or ArmV7? If you have `gcc` installed,
  that could be achieved by the following command: `gcc -march=native -Q --help=target|grep march`. In Linux, you can
  also check `/proc/cpuinfo` file for the required details.

### Using AI Tools

Contributions written with the help of AI tools (code assistants, agents, chat models) are welcome. We will not reject
a pull request because a model wrote part of it.

We do ask you to review the result yourself before you send it. You are the author of the pull request and you are
responsible for every line in it, no matter what typed it. A change the submitter has not read through costs
maintainers more time than it saves, and such pull requests may be closed without a detailed review.

Before opening a pull request, go through the change and check the following.

* **It is correct and you understand it.** You should be able to explain why each change is needed and answer review
  questions without going back to the model. Build the code, run the unit tests, and add tests for new behaviour.
* **Slop is removed.** AI tools produce a lot of text nobody needs. Remove it, in particular:
    * comments that restate the code (`/* increment the counter */`), narrate the change (`// Now handle the new
      case`), or talk to the reviewer;
    * long doc comments on small static functions;
    * plan, summary, notes or report files (`IMPLEMENTATION_NOTES.md`, `CHANGES_SUMMARY.md` and so on) and local tool
      state or settings; none of these belong in the repository;
    * checks for conditions that cannot happen, unused helpers, dead code and leftover debug output;
    * reformatting or refactoring of code unrelated to the change.

  Keep commit messages and pull request descriptions short and factual: what changed and why. Skip the headings,
  emoji and feature lists.
* **Coding standards are followed.** C and C++ code is formatted with `clang-format` using the project
  `.clang-format`, and new names follow the [C and C++ style guide](#c-and-c-styleguide). Lua code follows the
  [Lua style guide](lua_style.md) and passes `luacheck`. Commit messages use the [tags](#git-commit-messages) listed
  below.
* **Complexity is reasonable.** Rspamd runs on every message a mail server accepts, so performance matters. Check the
  algorithmic complexity of new code: no quadratic loops over message parts, headers, URLs or words, no allocations
  in tight loops that could be done once, and no blocking network or disk I/O in worker processes.
* **It fits the existing architecture.** Look for an existing helper before writing a new one (`lua_util`,
  `lua_redis`, `lua_maps`, selectors, the `rspamd_*` utilities in `src/libutil`). Put new code next to similar code
  and follow the conventions of the module you are changing. New dependencies, new configuration conventions or a
  second implementation of an existing subsystem should be discussed in an issue first.

You can use an AI tool for the review pass as well, but the final check is yours.

## Styleguides

### Git Commit Messages

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less (without tag)
* Reference issues and pull requests liberally after the first line
* Consider starting the commit message with an applicable tag:
    * [Minor] - minor issue/improvement not worth to mention in ChangeLog
    * [Feature] - a significant feature
    * [Fix] - bug fix
    * [CritFix] - critical bug fix worth a new version releasing
    * [Rework] - some significant logic rework
    * [Conf] - configuration change
    * [Rules] - rules change
    * [Test] - tests only
    * [Project] - build system, CI and other project infrastructure

### C and C++ styleguide

* Format the code with `clang-format` using the project `.clang-format`: tabs for indentation, 4 columns wide,
  pointers aligned to the right (`char *p`).
* Use `snake_case` for functions, variables and types. Public C functions carry the `rspamd_` prefix followed by the
  subsystem name (`rspamd_task_new`, `rspamd_url_find_tld`), structures are `struct rspamd_*`, and constant macros
  and enum values are `UPPER_CASE` with an `RSPAMD_` prefix. C++ code lives in the `rspamd` namespace or a nested one
  (`rspamd::html`, `rspamd::css`).
* Prefer C++20 for new modules and keep plain C style in existing C files. The code must build with GCC 10, so avoid
  library features that need a newer compiler, such as `std::bit_cast`.
* Use `ankerl::unordered_dense` (`contrib/ankerl/unordered_dense.h`) for hash maps and sets in C++, not
  `std::unordered_map` or `std::unordered_set`.
* Rspamd has its own `printf` implementation with different format specifiers. Read `src/libutil/printf.h` before
  writing logging or formatting code.

### Lua styleguide

Please use the following [Lua style guide](lua_style.md) when contributing changes to Lua code. This guide is both
applicable for rules, libraries and plugins.
