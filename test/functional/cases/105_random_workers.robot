*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         Collections
Library         String
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}              ${RSPAMD_TESTDIR}/configs/lua_test.conf
${RSPAMD_LUA_SCRIPT}   ${RSPAMD_TESTDIR}/lua/random_probe.lua
${RSPAMD_SCOPE}        Suite
${RSPAMD_URL_TLD}      ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
Workers Draw Different Random Numbers
  ${lines} =  Wait Until Keyword Succeeds  20x  0.5s  Probe Lines From Two Processes
  ${count} =  Get Line Count  ${lines}
  ${draws} =  Create List
  FOR  ${line}  IN  @{lines.splitlines()}
    ${m} =  Get Regexp Matches  ${line}  draws=(\\S+)  1
    Append To List  ${draws}  ${m}[0]
  END
  ${udraws} =  Remove Duplicates  ${draws}
  ${ndraws} =  Get Length  ${udraws}
  Should Be Equal As Integers  ${ndraws}  ${count}  msg=processes drew identical math.random sequences: ${draws}

*** Keywords ***
Probe Lines From Two Processes
  ${log} =  Get File  ${RSPAMD_TMPDIR}/rspamd.log  encoding_errors=ignore
  ${lines} =  Get Lines Matching Regexp  ${log}  .*RANDOM_PROBE type=.*
  ${count} =  Get Line Count  ${lines}
  Should Be True  ${count} >= 2  msg=expected probe lines from at least two processes, got ${count}
  ${pids} =  Create List
  FOR  ${line}  IN  @{lines.splitlines()}
    ${m} =  Get Regexp Matches  ${line}  pid=(\\d+)  1
    Append To List  ${pids}  ${m}[0]
  END
  ${upids} =  Remove Duplicates  ${pids}
  ${npids} =  Get Length  ${upids}
  Should Be True  ${npids} >= 2  msg=probes came from fewer than two pids: ${pids}
  RETURN  ${lines}
