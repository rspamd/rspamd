*** Settings ***
Suite Setup     Fuzzy Setup TCP Encrypted Siphash
Suite Teardown  Rspamd Redis Teardown
Resource        lib.robot

*** Test Cases ***
Fuzzy Add TCP Encrypted
  Fuzzy Multimessage Add Test

Fuzzy Delete TCP Encrypted
  Fuzzy Multimessage Delete Test

Fuzzy Overwrite TCP Encrypted
  Fuzzy Multimessage Overwrite Test

Fuzzy TCP Encrypted High Rate
  Fuzzy TCP High Rate Test
