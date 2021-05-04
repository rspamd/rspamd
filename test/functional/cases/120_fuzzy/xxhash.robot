*** Settings ***
Suite Setup     Fuzzy Setup Plain Xxhash
Suite Teardown  Rspamd Redis Teardown
Resource        lib.robot

*** Test Cases ***
Fuzzy Add
  Fuzzy Multimessage Add Test

Fuzzy Fuzzy
  [Tags]  isbroken
  Fuzzy Multimessage Fuzzy Test

Fuzzy Miss
  Fuzzy Multimessage Miss Test
