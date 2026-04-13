*** Settings ***
Suite Setup     Fuzzy Setup Plain Siphash
Suite Teardown  Rspamd Redis Teardown
Resource        lib.robot

*** Test Cases ***
Fuzzy Add
  Fuzzy Multimessage Add Test

Fuzzy Delete
  Fuzzy Multimessage Delete Test

Fuzzy Multi Flag
  Fuzzy Multimessage Multi Flag Test

Fuzzy Multi Flag Delete
  Fuzzy Multimessage Multi Flag Delete Test

Fuzzy Skip Hash Test
  Fuzzy Skip Hash Test Message