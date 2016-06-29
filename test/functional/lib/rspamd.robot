*** Settings ***
Library  Collections
Library  OperatingSystem
Library  Process

*** Keywords ***
Check Rspamc
  [Arguments]  ${result}  @{args}
  ${arglen} =  Get Length  ${args}
  ${expected_output} =  Set Variable If  ${arglen} < 1  success = true  @{args}[0]
  ${expected_rc} =  Set Variable If  ${arglen} < 2  0  @{args}[1]
  Follow Rspamd Log
  Should Contain  ${result.stdout}  ${expected_output}
  Should Be Equal As Integers  ${result.rc}  ${expected_rc}

Export Rspamd Vars To Suite
  [Arguments]  ${TMPDIR}  ${RSPAMD_LOGPOS}  ${RSPAMD_PID}
  Set Suite Variable  ${TMPDIR}
  Set Suite Variable  ${RSPAMD_LOGPOS}
  Set Suite Variable  ${RSPAMD_PID}

Export Rspamd Vars To Test
  [Arguments]  ${TMPDIR}  ${RSPAMD_LOGPOS}  ${RSPAMD_PID}
  Set Test Variable  ${TMPDIR}
  Set Test Variable  ${RSPAMD_LOGPOS}
  Set Test Variable  ${RSPAMD_PID}

Follow Rspamd Log
  ${RSPAMD_LOGPOS} =  Log Logs  ${TMPDIR}/rspamd.log  ${RSPAMD_LOGPOS}
  Run Keyword If  '${RSPAMD_SCOPE}' == 'Test'  Set Test Variable  ${RSPAMD_LOGPOS}
  ...  ELSE IF  '${RSPAMD_SCOPE}' == 'Suite'  Set Suite Variable  ${RSPAMD_LOGPOS}
  ...  ELSE  Fail  'RSPAMD_SCOPE must be Test or Suite'

Generic Setup
  ${TMPDIR}  ${RSPAMD_PID}  ${RSPAMD_LOGPOS} =  Run Rspamd
  Run Keyword If  '${RSPAMD_SCOPE}' == 'Test'  Export Rspamd Vars To Test  ${TMPDIR}  ${RSPAMD_LOGPOS}  ${RSPAMD_PID}
  ...  ELSE IF  '${RSPAMD_SCOPE}' == 'Suite'  Export Rspamd Vars To Suite  ${TMPDIR}  ${RSPAMD_LOGPOS}  ${RSPAMD_PID}
  ...  ELSE  Fail  'RSPAMD_SCOPE must be Test or Suite'

Generic Teardown
  Shutdown Rspamd                 ${RSPAMD_PID}
  Cleanup Temporary Directory     ${TMPDIR}

Log Logs
  [Arguments]                     ${logfile}  ${position}
  ${the_log}  ${position} =       Read Log From Position  ${logfile}  ${position}
  Log                             ${the_log}
  [Return]                        ${position}

Run Rspamc
  [Arguments]                     @{args}
  ${result} =                     Run Process  ${RSPAMC}  @{args}
  [Return]                        ${result}

Run Rspamd
  [Arguments]                     @{args}  &{kw}
  ${tmpdir} =                     Make Temporary Directory
  Set Directory Ownership         ${tmpdir}  ${RSPAMD_USER}  ${RSPAMD_GROUP}
  Set To Dictionary               ${RSPAMD_KEYWORDS}  TMPDIR=${tmpdir}
  Update Dictionary               ${RSPAMD_KEYWORDS}  ${kw}
  :FOR  ${i}  IN  @{args}
  \                               Set To Dictionary  ${RSPAMD_KEYWORDS}  ${i}  ${tmpdir}
  Populate Rspamd Config          ${CONFIG}  ${tmpdir}  &{RSPAMD_KEYWORDS}
  ${result} =                     Run Process  ${RSPAMD}  -u  ${RSPAMD_USER}  -g  ${RSPAMD_GROUP}  -c  ${tmpdir}/rspamd.conf
  ${rspamd_logpos} =              Log Logs  ${tmpdir}/rspamd.log  0
  Should Be Equal As Integers     ${result.rc}  0
  ${rspamd_pid} =                 Get File  ${tmpdir}/rspamd.pid
  [Return]                        ${tmpdir}  ${rspamd_pid}  ${rspamd_logpos}

Scan Message With Rspamc
  [Arguments]                     ${msg_file}
  ${result} =                     Run Rspamc  -p  -h  ${LOCAL_ADDR}:${PORT_NORMAL}  ${msg_file}
  [Return]                        ${result}
