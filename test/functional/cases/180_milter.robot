*** Settings ***
Suite Setup     Milter Setup
Suite Teardown  Generic Teardown
Library         Process
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${RSPAMD_SCOPE}  Suite
${URL_TLD}       ${TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
SIMPLE MILTER TEST
  ${result} =  Run Process  miltertest  -Dport\=${PORT_PROXY}  -Dhost\=${LOCAL_ADDR}  -s  ${TESTDIR}/lua/miltertest/mt1.lua
  Follow Rspamd Log
  Should Match Regexp  ${result.stderr}  ^$
  Should Match Regexp  ${result.stdout}  ^$
  Should Be Equal As Integers  ${result.rc}  0  msg=${result.stdout}  values=false

*** Keywords ***
Milter Setup
  Generic Setup  CONFIG=${TESTDIR}/configs/milter.conf
