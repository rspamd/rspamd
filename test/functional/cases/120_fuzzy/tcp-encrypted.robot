*** Settings ***
Suite Setup     Fuzzy Setup TCP Encrypted Siphash
Suite Teardown  Rspamd Redis Teardown
Resource        lib.robot

*** Test Cases ***
Fuzzy Add TCP Encrypted
  Fuzzy Multimessage Add Test

Fuzzy Delete TCP Encrypted
  Fuzzy Multimessage Delete Test

Fuzzy Multi Flag TCP Encrypted
  Fuzzy Multimessage Multi Flag Test

Fuzzy Multi Flag Delete TCP Encrypted
  Fuzzy Multimessage Multi Flag Delete Test

Fuzzy TCP Encrypted High Rate
  Fuzzy TCP High Rate Test
