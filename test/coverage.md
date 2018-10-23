Coverage collection explained
=============================

Hi mate. In short, you don't wanna know this. Believe me, you don't. Please, close this file and forget about it.

Surely? You still here?

Please, stop it until it's too late.

You were warned.


Preamble
--------
RSPAMD is written mainly in two languages: C and Lua. Coverage for each of them is being collected using different 
tools and approaches and is sent into [coveralls.io](https://coveralls.io).
Each approach is not quite compatible to other tools. This document describes how we crutch them to work together.


C coverage
----------
In general, pretty boring. When you run `cmake` with "-DENABLE_COVERAGE=ON" flag, it adds "--coverage" flag to both
CFLAGS and LDFLAGS. So that each run of generated binary will create `*.gcda` file containing coverage data.

However, there are some moment to highlight:

- RSPAMD is run under "nobody" user. Hence, directories and files should be writable for this user. 
- To make it possible, we explicitly run `umask 0000` in "build" and "functional" stages in .circleci/config.yml
- After run, we persist coverage data in "coverage.${CIRCLE\_JOB}.dump" during this build flow, see `capture_coverage_data`,
  to use it on the final stage.
- we user `cpp-coverals` because it is able to save data for coveralls without actually sending it. We send on our own
  along with Lua-coverage.

Lua coverage
------------
Lua coverage is collected for unit-tests and functional test suite. 
First part contains nothing interesting, just see `test/lua/tests.lua`.

"Functional" part is completely unobvious.

1. Coverage collecting is initiated and dumped in `test/functional/lua/test_coverage.lua` (there are a lot of comments inside).
   This file should be included on the very early stage of test run. Usually it's included via config.
2. Coverage is dumped into ${TMPDIR}/%{woker_name}.luacov.stats.out
3. All worker coverage reports are merged into `lua_coverage_report.json` (see `collect_lua_coverage()`)
4. finally, `lua_coverage_report.json` is persisted in build flow (see `functional` stage)

Altogether
----------

Finally, we get all the reports:

- `coverage.functional.dump` 
- `coverage.rspamd-test.dump`
- `lua_coverage_report.json`
- `unit_test_lua.json`

and merge them and send the resulting report using `test/functional/util/merge_coveralls.py`. Also, this scripts maps installed
paths into corresponding repository paths and removes unneeded files (i.e. test sources).
