*** Settings ***
Suite Setup     Fuzzy Setup TCP Siphash
Suite Teardown  Rspamd Redis Teardown
Resource        lib.robot

*** Test Cases ***
Fuzzy Add TCP
  Fuzzy Multimessage Add Test

Fuzzy Delete TCP
  Fuzzy Multimessage Delete Test

Fuzzy Multi Flag TCP
  Fuzzy Multimessage Multi Flag Test

Fuzzy TCP High Rate
  # Test that TCP is used after rate threshold exceeded
  Fuzzy TCP High Rate Test
