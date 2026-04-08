*** Settings ***
Suite Setup     Fuzzy Setup TCP Explicit Siphash
Suite Teardown  Rspamd Redis Teardown
Resource        lib.robot

*** Test Cases ***
Fuzzy Add TCP Explicit
  Fuzzy Multimessage Add Test

Fuzzy Delete TCP Explicit
  Fuzzy Multimessage Delete Test

Fuzzy Multi Flag TCP Explicit
  Fuzzy Multimessage Multi Flag Test

Fuzzy Multi Flag Delete TCP Explicit
  Fuzzy Multimessage Multi Flag Delete Test
