*** Settings ***
Suite Setup     New Setup
Suite Teardown  Generic Teardown
Library         Process
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}        ${TESTDIR}/configs/dkim_signing/milter.conf
${RSPAMD_SCOPE}  Suite
${URL_TLD}       ${TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
SINGLE SIGNATURE
  Milter Test  dkim_one.lua

MULTIPLE SIGNATURES
  Milter Test  dkim_many.lua

*** Keywords ***
Milter Test
  [Arguments]  ${mtlua}
  ${result} =  Run Process  miltertest  -Dport\=${PORT_PROXY}  -Dhost\=${LOCAL_ADDR}  -s  ${TESTDIR}/lua/miltertest/${mtlua}
  ...  cwd=${TESTDIR}/lua/miltertest
  Should Match Regexp  ${result.stderr}  ^$
  Log  ${result.rc}
  Log  ${result.stdout}
  Should Be Equal As Integers  ${result.rc}  0  msg=${result.stdout}  values=false
