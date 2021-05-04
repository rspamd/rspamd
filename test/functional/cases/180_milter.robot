*** Settings ***
Suite Setup     Milter Setup
Suite Teardown  Generic Teardown
Library         Process
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}        ${TESTDIR}/configs/milter.conf
${RSPAMD_SCOPE}  Suite
${URL_TLD}       ${TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
ACCEPT
  Milter Test  mt1.lua

REJECT
  Milter Test  mt2.lua

REWRITE SUBJECT
  Milter Test  mt3.lua

DEFER
  Milter Test  mt4.lua

COMBINED TEST
  Milter Test  combined.lua

*** Keywords ***
Milter Setup
  New Setup  URL_TLD=${URL_TLD}

Milter Test
  [Arguments]  ${mtlua}
  ${result} =  Run Process  miltertest  -Dport\=${PORT_PROXY}  -Dhost\=${LOCAL_ADDR}  -s  ${TESTDIR}/lua/miltertest/${mtlua}
  ...  cwd=${TESTDIR}/lua/miltertest
  Should Match Regexp  ${result.stderr}  ^$
  Log  ${result.rc}
  Log  ${result.stdout}
  Should Be Equal As Integers  ${result.rc}  0  msg=${result.stdout}  values=false
