*** Settings ***
Suite Setup     Statistics Setup
Suite Teardown  Statistics Teardown
Resource        lib.robot

*** Variables ***
${STATS_BACKEND}  mmap
${STATS_HASH}   hash = "compat";

*** Test Cases ***
Learn
  Learn Test

Relearn
  Relearn Test

Empty Part
  Empty Part Test
