*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Test Tags       miltertest
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/milter_slow_upstream.conf
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
SLOW UPSTREAM RETURNS ONE TEMPFAIL AND KEEPS THE CONNECTION
  Milter Test  slow_upstream.lua
  ${log} =  Get File  ${RSPAMD_TMPDIR}/rspamd.log  encoding_errors=ignore
  # The failure has to come from the backend error handler, not from the
  # initial upstream selection
  Should Contain  ${log}  abnormally closing connection from backend
  Should Contain  ${log}  cannot select upstream for default

*** Keywords ***
Milter Test
  [Arguments]  ${mtlua}
  Skip If  not ${HAVE_MILTERTEST}  msg=miltertest not installed
  ${result} =  Run Process  miltertest  -Dport\=${RSPAMD_PORT_PROXY}  -Dhost\=${RSPAMD_LOCAL_ADDR}  -s  ${RSPAMD_TESTDIR}/lua/miltertest/${mtlua}
  ...  cwd=${RSPAMD_TESTDIR}/lua/miltertest
  Should Match Regexp  ${result.stderr}  ^$
  Log  ${result.rc}
  Log  ${result.stdout}
  Should Be Equal As Integers  ${result.rc}  0  msg=${result.stdout}  values=false
