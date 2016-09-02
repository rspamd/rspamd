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
  Should Be Equal As Integers  ${result.rc}  ${rc}

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

Custom Follow Rspamd Log
  [Arguments]  ${logfile}  ${logpos}  ${logpos_var}  ${scope}
  ${logpos} =  Log Logs  ${logfile}  ${logpos}
  Run Keyword If  '${scope}' == 'Test'  Set Test Variable  ${${logpos_var}}  ${logpos}
  ...  ELSE IF  '${scope}' == 'Suite'  Set Suite Variable  ${${logpos_var}}  ${logpos}
  ...  ELSE  Fail  'scope must be Test or Suite'

Follow Rspamd Log
  ${RSPAMD_LOGPOS} =  Log Logs  ${TMPDIR}/rspamd.log  ${RSPAMD_LOGPOS}
  Run Keyword If  '${RSPAMD_SCOPE}' == 'Test'  Set Test Variable  ${RSPAMD_LOGPOS}
  ...  ELSE IF  '${RSPAMD_SCOPE}' == 'Suite'  Set Suite Variable  ${RSPAMD_LOGPOS}
  ...  ELSE  Fail  'RSPAMD_SCOPE must be Test or Suite'

Generic Setup
  [Arguments]  @{vargs}
  &{d} =  Run Rspamd  @{vargs}
  ${keys} =  Get Dictionary Keys  ${d}
  : FOR  ${i}  IN  @{keys}
  \  Run Keyword If  '${RSPAMD_SCOPE}' == 'Suite'  Set Suite Variable  ${${i}}  &{d}[${i}]
  \  ...  ELSE IF  '${RSPAMD_SCOPE}' == 'Test'  Set Test Variable  ${${i}}  &{d}[${i}]
  \  ...  ELSE  Fail  'RSPAMD_SCOPE must be Test or Suite'

Generic Teardown
  Shutdown Process With Children  ${RSPAMD_PID}
  Cleanup Temporary Directory  ${TMPDIR}

Log Logs
  [Arguments]  ${logfile}  ${position}
  ${the_log}  ${position} =  Read Log From Position  ${logfile}  ${position}
  Log  ${the_log}
  [Return]  ${position}

Redis HSET
  [Arguments]  ${hash}  ${key}  ${value}
  ${result} =  Run Process  redis-cli  -h  ${REDIS_ADDR}  -p  ${REDIS_PORT}
  ...  HSET  ${hash}  ${key}  ${value}
  Run Keyword If  ${result.rc} != 0  Log  ${result.stderr}
  Log  ${result.stdout}
  Should Be Equal As Integers  ${result.rc}  0

Run Redis
  ${template} =  Get File  ${TESTDIR}/configs/redis-server.conf
  ${config} =  Replace Variables  ${template}
  Create File  ${TMPDIR}/redis-server.conf  ${config}
  Log  ${config}
  ${result} =  Run Process  redis-server  ${TMPDIR}/redis-server.conf
  Run Keyword If  ${result.rc} != 0  Log  ${result.stderr}
  Should Be Equal As Integers  ${result.rc}  0
  Wait Until Created  ${TMPDIR}/redis.pid
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
  [Arguments]  @{vargs}  &{kwargs}
  ${has_CONFIG} =  Evaluate  'CONFIG' in $kwargs
  ${CONFIG} =  Set Variable If  ${has_CONFIG} == True  &{kwargs}[CONFIG]  ${CONFIG}
  &{d} =  Create Dictionary
  ${tmpdir} =  Make Temporary Directory
  Set Directory Ownership  ${tmpdir}  ${RSPAMD_USER}  ${RSPAMD_GROUP}
  ${template} =  Get File  ${CONFIG}
  : FOR  ${i}  IN  @{vargs}
  \  ${newvalue} =  Replace Variables  ${${i}}
  \  Set To Dictionary  ${d}  ${i}=${newvalue}
  ${config} =  Replace Variables  ${template}
  ${config} =  Replace Variables  ${config}
  Log  ${config}
  Create File  ${tmpdir}/rspamd.conf  ${config}
  ${result} =  Run Process  ${RSPAMD}  -u  ${RSPAMD_USER}  -g  ${RSPAMD_GROUP}
  ...  -c  ${tmpdir}/rspamd.conf  env:TMPDIR=${tmpdir}  env:LD_LIBRARY_PATH=${TESTDIR}/../../contrib/aho-corasick
  Run Keyword If  ${result.rc} != 0  Log  ${result.stderr}
  ${rspamd_logpos} =  Log Logs  ${tmpdir}/rspamd.log  0
  Should Be Equal As Integers  ${result.rc}  0
  Wait Until Created  ${tmpdir}/rspamd.pid
  ${rspamd_pid} =  Get File  ${tmpdir}/rspamd.pid
  Set To Dictionary  ${d}  RSPAMD_LOGPOS=${rspamd_logpos}  RSPAMD_PID=${rspamd_pid}  TMPDIR=${tmpdir}
  [Return]  &{d}

Scan Message With Rspamc
  [Arguments]  ${msg_file}  @{vargs}
  ${result} =  Run Rspamc  -p  -h  ${LOCAL_ADDR}:${PORT_NORMAL}  @{vargs}  ${msg_file}
  [Return]  ${result}

Sync Fuzzy Storage
  ${result} =  Run Process  ${RSPAMADM}  control  -s  ${TMPDIR}/rspamd.sock  fuzzy_sync
  Log  ${result.stdout}
  Follow Rspamd Log
  Sleep  0.005s  Try give fuzzy storage time to sync
