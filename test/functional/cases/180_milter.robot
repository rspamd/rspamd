*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/milter.conf
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

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
Milter Test
  [Arguments]  ${mtlua}
  ${result} =  Run Process  miltertest  -Dport\=${RSPAMD_PORT_PROXY}  -Dhost\=${RSPAMD_LOCAL_ADDR}  -s  ${RSPAMD_TESTDIR}/lua/miltertest/${mtlua}
  ...  cwd=${RSPAMD_TESTDIR}/lua/miltertest
  Should Match Regexp  ${result.stderr}  ^$
  Log  ${result.rc}
  Log  ${result.stdout}
  Should Be Equal As Integers  ${result.rc}  0  msg=${result.stdout}  values=false
