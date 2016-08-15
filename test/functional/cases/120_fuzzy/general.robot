*** Settings ***
Suite Setup     Fuzzy Setup Plain Siphash
Suite Teardown  Generic Teardown
Resource        lib.robot

*** Test Cases ***
Fuzzy Add
  Fuzzy Multimessage Add Test

Fuzzy Delete
  Fuzzy Multimessage Delete Test

Fuzzy Overwrite
  Fuzzy Multimessage Overwrite Test
