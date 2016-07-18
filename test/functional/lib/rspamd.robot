*** Settings ***
Library         Collections
Library         OperatingSystem
Library         Process

*** Keywords ***
Check Rspamc
  [Arguments]  ${result}  @{args}  &{kwargs}
  Follow Rspamd Log
  Run Keyword If  ${result.rc} != 0  Log  ${result.stderr}
  ${has_rc} =  Evaluate  'rc' in $kwargs
  ${inverse} =  Evaluate  'inverse' in $kwargs
  ${re} =  Evaluate  're' in $kwargs
  ${rc} =  Set Variable If  ${has_rc} == True  &{kwargs}[rc]  0
  : FOR  ${i}  IN  @{args}
  \  Run Keyword If  ${re} == True  Check Rspamc Match Regexp  ${result.stdout}  ${i}  ${inverse}
  \  ...  ELSE  Check Rspamc Match String  ${result.stdout}  ${i}  ${inverse}
  Run Keyword If  @{args} == @{EMPTY}  Check Rspamc Match Default  ${result.stdout}  ${inverse}
  ${rc_nocheck} =  Evaluate  'rc_nocheck' in $kwargs
  Run Keyword If  ${rc_nocheck} == True  Return From Keyword
  Run Keyword If  ${inverse} == False  Should Be Equal As Integers  ${result.rc}  ${rc}
  ...  ELSE  Should Not Be Equal As Integers  ${result.rc}  ${rc}

Check Rspamc Match Default
  [Arguments]  ${subject}  ${inverse}
  Run Keyword If  ${inverse} == False  Should Contain  ${subject}  success = true
  ...  ELSE  Should Not Contain  ${subject}  success = true

Check Rspamc Match Regexp
  [Arguments]  ${subject}  ${re}  ${inverse}
  Run Keyword If  ${inverse} == False  Should Match Regexp  ${subject}  ${re}
  ...  ELSE  Should Not Match Regexp ${subject}  ${re}

Check Rspamc Match String
  [Arguments]  ${subject}  ${str}  ${inverse}
  Run Keyword If  ${inverse} == False  Should Contain  ${subject}  ${str}
  ...  ELSE  Should Not Contain  ${subject}  ${str}

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
  [Arguments]  @{vargs}
  ${TMPDIR}  ${RSPAMD_PID}  ${RSPAMD_LOGPOS} =  Run Rspamd  @{vargs}
  Run Keyword If  '${RSPAMD_SCOPE}' == 'Test'  Export Rspamd Vars To Test  ${TMPDIR}  ${RSPAMD_LOGPOS}  ${RSPAMD_PID}
  ...  ELSE IF  '${RSPAMD_SCOPE}' == 'Suite'  Export Rspamd Vars To Suite  ${TMPDIR}  ${RSPAMD_LOGPOS}  ${RSPAMD_PID}
  ...  ELSE  Fail  'RSPAMD_SCOPE must be Test or Suite'

Generic Teardown
  Shutdown Process  ${RSPAMD_PID}
  Cleanup Temporary Directory  ${TMPDIR}

Log Logs
  [Arguments]  ${logfile}  ${position}
  ${the_log}  ${position} =  Read Log From Position  ${logfile}  ${position}
  Log  ${the_log}
  [Return]  ${position}

Run Redis
  ${template} =  Get File  ${TESTDIR}/configs/redis-server.conf
  ${config} =  Replace Variables  ${template}
  Create File  ${TMPDIR}/redis-server.conf  ${config}
  Log  ${config}
  ${result} =  Run Process  redis-server  ${TMPDIR}/redis-server.conf
  Run Keyword If  ${result.rc} != 0  Log  ${result.stderr}
  Should Be Equal As Integers  ${result.rc}  0
  ${REDIS_PID} =  Get File  ${TMPDIR}/redis.pid
  Run Keyword If  '${REDIS_SCOPE}' == 'Test'  Set Test Variable  ${REDIS_PID}
  ...  ELSE IF  '${REDIS_SCOPE}' == 'Suite'  Set Suite Variable  ${REDIS_PID}
  ${redis_log} =  Get File  ${TMPDIR}/redis.log
  Log  ${redis_log}

Run Rspamc
  [Arguments]  @{args}
  ${result} =  Run Process  ${RSPAMC}  @{args}  env:LD_LIBRARY_PATH=${TESTDIR}/../../contrib/aho-corasick
  [Return]  ${result}

Run Rspamd
  [Arguments]  @{vargs}
  ${TMPDIR} =  Make Temporary Directory
  Set Directory Ownership  ${TMPDIR}  ${RSPAMD_USER}  ${RSPAMD_GROUP}
  ${template} =  Get File  ${CONFIG}
  : FOR  ${i}  IN  @{vargs}
  \  ${newvalue} =  Replace Variables  ${${i}}
  \  Set Suite Variable  ${${i}}  ${newvalue}
  \  Run Keyword If  '${RSPAMD_SCOPE}' == 'Test'  Set Test Variable  ${${i}}  ${newvalue}
  \  ...  ELSE IF  '${RSPAMD_SCOPE}' == 'Suite'  Set Suite Variable  ${${i}}  ${newvalue}
  \  ...  ELSE  Fail  'RSPAMD_SCOPE must be Test or Suite'
  ${config} =  Replace Variables  ${template}
  Log  ${config}
  Create File  ${TMPDIR}/rspamd.conf  ${config}
  ${result} =  Run Process  ${RSPAMD}  -u  ${RSPAMD_USER}  -g  ${RSPAMD_GROUP}
  ...  -c  ${TMPDIR}/rspamd.conf  env:LD_LIBRARY_PATH=${TESTDIR}/../../contrib/aho-corasick
  Run Keyword If  ${result.rc} != 0  Log  ${result.stderr}
  ${rspamd_logpos} =  Log Logs  ${TMPDIR}/rspamd.log  0
  Should Be Equal As Integers  ${result.rc}  0
  ${rspamd_pid} =  Get File  ${TMPDIR}/rspamd.pid
  [Return]  ${TMPDIR}  ${rspamd_pid}  ${rspamd_logpos}

Scan Message With Rspamc
  [Arguments]  ${msg_file}
  ${result} =  Run Rspamc  -p  -h  ${LOCAL_ADDR}:${PORT_NORMAL}  ${msg_file}
  [Return]  ${result}

Sync Fuzzy Storage
  ${result} =  Run Process  ${RSPAMADM}  control  -s  ${TMPDIR}/rspamd.sock  fuzzy_sync
  Log  ${result.stdout}
  Follow Rspamd Log
