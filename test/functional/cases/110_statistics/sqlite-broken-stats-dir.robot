*** Settings ***
Suite Setup     Generic Setup
Suite Teardown  Generic Teardown
Resource        ${TESTDIR}/lib/rspamd.robot
Resource        lib.robot

*** Variables ***
${STATS_BACKEND}  sqlite3
${STATS_PATH_CACHE}  path = "/does/not/exist/bayes-cache.sqlite";
${STATS_PATH_HAM}  path = "/does/not/exist/bayes-ham.sqlite";
${STATS_PATH_SPAM}  path = "/does/not/exist/bayes-spam.sqlite";

*** Test Cases ***
Broken Stats Directory
  Broken Learn Test
