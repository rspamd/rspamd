*** Settings ***
Suite Setup     Statistics Setup
Suite Teardown  Statistics Teardown
Resource        lib.robot

*** Variables ***
${STATS_BACKEND}  sqlite3
${STATS_HASH}   hash = "siphash";

*** Test Cases ***
Learn
  Learn Test

Relearn
  Relearn Test

Empty Part
  Empty Part Test
