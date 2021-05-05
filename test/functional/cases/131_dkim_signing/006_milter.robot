*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/dkim_signing/milter.conf
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
SINGLE SIGNATURE
  Milter Test  dkim_one.lua

MULTIPLE SIGNATURES
  Milter Test  dkim_many.lua

*** Keywords ***
Milter Test
  [Arguments]  ${mtlua}
  ${result} =  Run Process  miltertest  -Dport\=${RSPAMD_PORT_PROXY}  -Dhost\=${RSPAMD_LOCAL_ADDR}  -s  ${RSPAMD_TESTDIR}/lua/miltertest/${mtlua}
  ...  cwd=${RSPAMD_TESTDIR}/lua/miltertest
  Should Match Regexp  ${result.stderr}  ^$
  Log  ${result.rc}
  Log  ${result.stdout}
  Should Be Equal As Integers  ${result.rc}  0  msg=${result.stdout}  values=false
