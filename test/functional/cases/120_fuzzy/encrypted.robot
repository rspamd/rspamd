*** Settings ***
Suite Setup     Encrypted Fuzzy Setup
Suite Teardown  Generic Teardown
Resource        lib.robot

*** Test Cases ***
Fuzzy Add
  Fuzzy Add Test

Fuzzy Delete
  Fuzzy Delete Test

Fuzzy Overwrite
  Fuzzy Overwrite Test

*** Keywords ***
Encrypted Fuzzy Setup
  Set Suite Variable  ${SETTINGS_FUZZY_WORKER}  "keypair": {"pubkey": "${KEY_PUB1}", "privkey": "${KEY_PVT1}"}; "encrypted_only": true;
  Set Suite Variable  ${SETTINGS_FUZZY_CHECK}  encryption_key = "${KEY_PUB1}";
  Generic Setup
