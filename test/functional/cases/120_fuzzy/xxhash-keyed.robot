*** Settings ***
Suite Setup     Fuzzy Setup Keyed Xxhash
Suite Teardown  Fuzzy Teardown
Resource        lib.robot

*** Test Cases ***
Fuzzy Add
  Fuzzy Multimessage Add Test

Fuzzy Fuzzy
  [Tags]  isbroken
  Fuzzy Multimessage Fuzzy Test

Fuzzy Miss
  Fuzzy Multimessage Miss Test
