*** Settings ***
Suite Setup     Statistics Setup
Suite Teardown  Statistics Teardown
Resource        lib.robot

*** Variables ***
${STATS_BACKEND}  mmap
${STATS_HASH}   hash = "compat";
${STATS_PATH_CACHE}  name = "sqlite3"; path = "\${TMPDIR}/learn_cache.db";

*** Test Cases ***
Learn
  Learn Test

Relearn
  Relearn Test

Empty Part
  Empty Part Test
