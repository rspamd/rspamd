*** Settings ***
Suite Setup     Fuzzy Setup Encrypted Siphash
Suite Teardown  Rspamd Redis Teardown
Resource        lib.robot

*** Test Cases ***
Fuzzy Add
  Fuzzy Multimessage Add Test

Fuzzy Fuzzy
  Fuzzy Multimessage Fuzzy Test

Fuzzy Miss
  Fuzzy Multimessage Miss Test

Fuzzy Fuzzy Dynamic Key
  Set Suite Variable  ${RSPAMD_FUZZY_ENCRYPTION_KEY}  "mbggdnw3tdx7r3ruakjecpf5hcqr4cb4nmdp1fxynx3drbyujb3y"
  Fuzzy Multimessage Fuzzy Encrypted Test

Fuzzy Fuzzy Another Dynamic Key
  Set Suite Variable  ${RSPAMD_FUZZY_ENCRYPTION_KEY}  "c98d3pnb7ejjz1rkobumbbjzo5pbeh64rj68dudy8w7h8mipg1by"
  Fuzzy Multimessage Fuzzy Encrypted Test
