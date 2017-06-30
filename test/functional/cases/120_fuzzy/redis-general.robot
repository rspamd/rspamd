*** Settings ***
Suite Setup     Fuzzy Redis General Setup
Suite Teardown  Fuzzy Redis General Teardown
Resource        lib.robot

*** Variables ***
${REDIS_SCOPE}  Suite

*** Test Cases ***
Fuzzy Add
  Fuzzy Multimessage Add Test

Fuzzy Fuzzy
  Fuzzy Multimessage Fuzzy Test

Fuzzy Delete
  Fuzzy Multimessage Delete Test

Fuzzy Overwrite
  Fuzzy Multimessage Overwrite Test

*** Keywords ***
Fuzzy Redis General Setup
  ${tmpdir} =  Make Temporary Directory
  Set Suite Variable  ${TMPDIR}  ${tmpdir}
  Run Redis
  Fuzzy Setup Generic  siphash  backend \= "redis";  ${EMPTY}  TMPDIR=${TMPDIR}

Fuzzy Redis General Teardown
  Normal Teardown
  Shutdown Process With Children  ${REDIS_PID}
