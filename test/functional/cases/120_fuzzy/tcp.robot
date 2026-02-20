*** Settings ***
Suite Setup     Fuzzy Setup TCP Siphash
Suite Teardown  Rspamd Redis Teardown
Resource        lib.robot

*** Test Cases ***
Fuzzy Add TCP
  Fuzzy Multimessage Add Test

Fuzzy Delete TCP
  Fuzzy Multimessage Delete Test

Fuzzy Overwrite TCP
  Fuzzy Multimessage Overwrite Test

Fuzzy TCP High Rate
  # Test that TCP is used after rate threshold exceeded
  Fuzzy TCP High Rate Test
