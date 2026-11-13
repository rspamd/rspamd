*** Settings ***
Library         Process
Library         OperatingSystem
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Variables       ${RSPAMD_TESTDIR}/lib/vars.py
Suite Setup     Controller Queries Setup
Test Template   Verify Controller Queries
Test Timeout    1 minute
Test Tags       controller  ownership

*** Test Cases ***
Passwordless Read Without Arguments       read-empty
Passwordless Read With Arguments          read-values
Passwordless Privileged Without Arguments  write-empty
Passwordless Privileged With Arguments     write-values
Custom Command Copies Query Arguments      custom

*** Keywords ***
Controller Queries Setup
  Set Suite Variable  ${QUERY_RESULTS}  ${OUTPUTDIR}/controller-queries
  Create Directory  ${QUERY_RESULTS}

Verify Controller Queries
  [Arguments]  ${case}
  ${python} =  Evaluate  sys.executable  modules=sys
  ${result} =  Run Process  ${python}  ${RSPAMD_TESTDIR}/util/controller_queries.py
  ...  --rspamd  ${RSPAMD}  --source  ${TOPDIR}
  ...  --case  ${case}  --output-dir  ${QUERY_RESULTS}
  ...  timeout=55s  on_timeout=kill
  Log  ${result.stdout}
  Should Be Equal As Integers  ${result.rc}  0  ${result.stdout}\n${result.stderr}
