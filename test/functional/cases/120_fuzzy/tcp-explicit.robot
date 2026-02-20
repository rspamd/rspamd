*** Settings ***
Suite Setup     Fuzzy Setup TCP Explicit Siphash
Suite Teardown  Rspamd Redis Teardown
Resource        lib.robot

*** Test Cases ***
Fuzzy Add TCP Explicit
  Fuzzy Multimessage Add Test

Fuzzy Delete TCP Explicit
  Fuzzy Multimessage Delete Test

Fuzzy Overwrite TCP Explicit
  Fuzzy Multimessage Overwrite Test
