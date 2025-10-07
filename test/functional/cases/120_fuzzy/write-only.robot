*** Settings ***
Suite Setup     Fuzzy Setup Write Only
Suite Teardown  Rspamd Redis Teardown
Resource        lib.robot

*** Test Cases ***
Fuzzy Add
  # Add hashes without checking (write-only mode doesn't send CHECK)
  Fuzzy Multimessage Add Test Write Only

Fuzzy Write Only No Check
  # In write-only mode, CHECK requests are not sent
  # So scanning should not find symbols even though hashes are in storage
  Fuzzy Multimessage Write Only No Check Test

Fuzzy Miss
  # Random messages should not match
  Fuzzy Multimessage Miss Test
