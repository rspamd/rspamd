*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Test Cases ***
CONTROL STAT
  [Documentation]  Test control socket stat command
  ${result} =  Run Control Command  stat  ${RSPAMD_TMPDIR}/rspamd.sock
  Should Be Equal As Integers  ${result.rc}  0
  Should Contain  ${result.stdout}  workers
  Should Contain  ${result.stdout}  total

CONTROL STAT JSON
  [Documentation]  Test control socket stat command with JSON output
  ${result} =  Run Control Command JSON  stat  ${RSPAMD_TMPDIR}/rspamd.sock
  Should Be Equal As Integers  ${result.rc}  0
  Should Contain  ${result.stdout}  "workers"
  Should Contain  ${result.stdout}  "total"

CONTROL RERESOLVE
  [Documentation]  Test control socket reresolve command
  ${result} =  Run Control Command  reresolve  ${RSPAMD_TMPDIR}/rspamd.sock
  Should Be Equal As Integers  ${result.rc}  0

CONTROL FUZZY SYNC
  [Documentation]  Test control socket fuzzy_sync command
  ${result} =  Run Control Command  fuzzy_sync  ${RSPAMD_TMPDIR}/rspamd.sock
  Should Be Equal As Integers  ${result.rc}  0

CONTROL COMPOSITES STATS
  [Documentation]  Test control socket composites_stats command
  ${result} =  Run Control Command  composites_stats  ${RSPAMD_TMPDIR}/rspamd.sock
  Should Be Equal As Integers  ${result.rc}  0
  Should Contain  ${result.stdout}  checked_slow

CONTROL COMPOSITES STATS JSON
  [Documentation]  Test control socket composites_stats command with JSON output
  ${result} =  Run Control Command JSON  composites_stats  ${RSPAMD_TMPDIR}/rspamd.sock
  Should Be Equal As Integers  ${result.rc}  0
  Should Contain  ${result.stdout}  checked_slow

CONTROL MULTIPLE COMMANDS
  [Documentation]  Test multiple control socket commands in sequence to verify ID matching
  ${result1} =  Run Control Command  stat  ${RSPAMD_TMPDIR}/rspamd.sock
  Should Be Equal As Integers  ${result1.rc}  0
  ${result2} =  Run Control Command  reresolve  ${RSPAMD_TMPDIR}/rspamd.sock
  Should Be Equal As Integers  ${result2.rc}  0
  ${result3} =  Run Control Command  composites_stats  ${RSPAMD_TMPDIR}/rspamd.sock
  Should Be Equal As Integers  ${result3.rc}  0
  ${result4} =  Run Control Command  stat  ${RSPAMD_TMPDIR}/rspamd.sock
  Should Be Equal As Integers  ${result4.rc}  0
