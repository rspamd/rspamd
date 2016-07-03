*** Settings ***
Suite Setup     Generic Setup
Suite Teardown  Generic Teardown
Resource        lib.robot

*** Variables ***
${SETTINGS_FUZZY_WORKER}  ${EMPTY}
${SETTINGS_FUZZY_CHECK}  ${EMPTY}

*** Test Cases ***
Fuzzy Add
  Fuzzy Add Test

Fuzzy Delete
  Fuzzy Delete Test

Fuzzy Overwrite
  Fuzzy Overwrite Test
