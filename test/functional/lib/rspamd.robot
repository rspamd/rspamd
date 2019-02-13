*** Settings ***
Library         Collections
Library         OperatingSystem
Library         Process

*** Keywords ***
Check Controller Errors
  @{result} =  HTTP  GET  ${LOCAL_ADDR}  ${PORT_CONTROLLER}  /errors
  Should Be Equal As Integers  @{result}[0]  200
  Log  @{result}[1]

Check Pidfile
  [Arguments]  ${pidfile}  ${timeout}=1 min
  Wait Until Created  ${pidfile}  timeout=${timeout}
  ${size} =  Get File Size  ${pidfile}
  Should Not Be Equal As Integers  ${size}  0

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
  [Arguments]  @{vargs}  &{kwargs}
  &{d} =  Run Rspamd  @{vargs}  &{kwargs}
  ${keys} =  Get Dictionary Keys  ${d}
  : FOR  ${i}  IN  @{keys}
  \  Run Keyword If  '${RSPAMD_SCOPE}' == 'Suite'  Set Suite Variable  ${${i}}  &{d}[${i}]
  \  ...  ELSE IF  '${RSPAMD_SCOPE}' == 'Test'  Set Test Variable  ${${i}}  &{d}[${i}]
  \  ...  ELSE  Fail  'RSPAMD_SCOPE must be Test or Suite'

Generic Teardown
  [Arguments]  @{ports}
  Run Keyword If  '${CONTROLLER_ERRORS}' == 'True'  Check Controller Errors
  Shutdown Process With Children  ${RSPAMD_PID}
  Log does not contain segfault record
  Save Run Results  ${TMPDIR}  rspamd.log redis.log rspamd.conf clickhouse-server.log clickhouse-server.err.log clickhouse-config.xml
  Collect Lua Coverage
  Cleanup Temporary Directory  ${TMPDIR}

Log does not contain segfault record
  ${log} =  Get File  ${TMPDIR}/rspamd.log
  Should not contain  ${log}  Segmentation fault:  msg=Segmentation fault detected

Log Logs
  [Arguments]  ${logfile}  ${position}
  ${the_log}  ${position} =  Read Log From Position  ${logfile}  ${position}
  Log  ${the_log}
  [Return]  ${position}

Normal Teardown
  ${port_normal} =  Create List  ${SOCK_STREAM}  ${LOCAL_ADDR}  ${PORT_NORMAL}
  ${port_controller} =  Create List  ${SOCK_STREAM}  ${LOCAL_ADDR}  ${PORT_CONTROLLER}
  ${ports} =  Create List  ${port_normal}  ${port_controller}
  Generic Teardown  @{ports}

Redis HSET
  [Arguments]  ${hash}  ${key}  ${value}
  ${result} =  Run Process  redis-cli  -h  ${REDIS_ADDR}  -p  ${REDIS_PORT}
  ...  HSET  ${hash}  ${key}  ${value}
  Run Keyword If  ${result.rc} != 0  Log  ${result.stderr}
  Log  ${result.stdout}
  Should Be Equal As Integers  ${result.rc}  0

Redis SET
  [Arguments]  ${key}  ${value}
  ${result} =  Run Process  redis-cli  -h  ${REDIS_ADDR}  -p  ${REDIS_PORT}
  ...  SET  ${key}  ${value}
  Run Keyword If  ${result.rc} != 0  Log  ${result.stderr}
  Log  ${result.stdout}
  Should Be Equal As Integers  ${result.rc}  0

Run Redis
  ${has_TMPDIR} =  Evaluate  'TMPDIR'
  ${tmpdir} =  Run Keyword If  '${has_TMPDIR}' == 'True'  Set Variable  &{kwargs}[TMPDIR]
  ...  ELSE  Make Temporary Directory
  ${template} =  Get File  ${TESTDIR}/configs/redis-server.conf
  ${config} =  Replace Variables  ${template}
  Create File  ${TMPDIR}/redis-server.conf  ${config}
  Log  ${config}
  ${result} =  Run Process  redis-server  ${TMPDIR}/redis-server.conf
  Run Keyword If  ${result.rc} != 0  Log  ${result.stderr}
  Should Be Equal As Integers  ${result.rc}  0
  Wait Until Keyword Succeeds  30 sec  1 sec  Check Pidfile  ${TMPDIR}/redis.pid
  Wait Until Keyword Succeeds  30 sec  1 sec  TCP Connect  ${REDIS_ADDR}  ${REDIS_PORT}
  ${REDIS_PID} =  Get File  ${TMPDIR}/redis.pid
  Run Keyword If  '${REDIS_SCOPE}' == 'Test'  Set Test Variable  ${REDIS_PID}
  ...  ELSE IF  '${REDIS_SCOPE}' == 'Suite'  Set Suite Variable  ${REDIS_PID}
  ${redis_log} =  Get File  ${TMPDIR}/redis.log
  Log  ${redis_log}

Run Nginx
  ${template} =  Get File  ${TESTDIR}/configs/nginx.conf
  ${config} =  Replace Variables  ${template}
  Create File  ${TMPDIR}/nginx.conf  ${config}
  Log  ${config}
  ${result} =  Run Process  nginx  -c  ${TMPDIR}/nginx.conf
  Run Keyword If  ${result.rc} != 0  Log  ${result.stderr}
  Should Be Equal As Integers  ${result.rc}  0
  Wait Until Keyword Succeeds  30 sec  1 sec  Check Pidfile  ${TMPDIR}/nginx.pid
  Wait Until Keyword Succeeds  30 sec  1 sec  TCP Connect  ${NGINX_ADDR}  ${NGINX_PORT}
  ${NGINX_PID} =  Get File  ${TMPDIR}/nginx.pid
  Run Keyword If  '${NGINX_SCOPE}' == 'Test'  Set Test Variable  ${NGINX_PID}
  ...  ELSE IF  '${NGINX_SCOPE}' == 'Suite'  Set Suite Variable  ${NGINX_PID}
  ${nginx_log} =  Get File  ${TMPDIR}/nginx.log
  Log  ${nginx_log}

Run Rspamc
  [Arguments]  @{args}
  ${result} =  Run Process  ${RSPAMC}  -t  60  --header  Queue-ID\=${TEST NAME}  @{args}  env:LD_LIBRARY_PATH=${TESTDIR}/../../contrib/aho-corasick
  Log  ${result.stdout}
  [Return]  ${result}

Run Rspamd
  [Arguments]  @{vargs}  &{kwargs}
  ${has_CONFIG} =  Evaluate  'CONFIG' in $kwargs
  ${has_TMPDIR} =  Evaluate  'TMPDIR' in $kwargs
  ${CONFIG} =  Set Variable If  '${has_CONFIG}' == 'True'  &{kwargs}[CONFIG]  ${CONFIG}
  &{d} =  Create Dictionary
  ${tmpdir} =  Run Keyword If  '${has_TMPDIR}' == 'True'  Set Variable  &{kwargs}[TMPDIR]
  ...  ELSE  Make Temporary Directory
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
  ...  -c  ${tmpdir}/rspamd.conf  env:TMPDIR=${tmpdir}  env:DBDIR=${tmpdir}  env:LD_LIBRARY_PATH=${TESTDIR}/../../contrib/aho-corasick
  Run Keyword If  ${result.rc} != 0  Log  ${result.stderr}
  ${rspamd_logpos} =  Log Logs  ${tmpdir}/rspamd.log  0
  Should Be Equal As Integers  ${result.rc}  0
  Wait Until Keyword Succeeds  30 sec  1 sec  Check Pidfile  ${tmpdir}/rspamd.pid
  ${rspamd_pid} =  Get File  ${tmpdir}/rspamd.pid
  Set To Dictionary  ${d}  RSPAMD_LOGPOS=${rspamd_logpos}  RSPAMD_PID=${rspamd_pid}  TMPDIR=${tmpdir}
  [Return]  &{d}

Scan Message With Rspamc
  [Arguments]  ${msg_file}  @{vargs}
  ${result} =  Run Rspamc  -p  -h  ${LOCAL_ADDR}:${PORT_NORMAL}  @{vargs}  ${msg_file}
  [Return]  ${result}

Simple Teardown
  ${port_normal} =  Create List  ${SOCK_STREAM}  ${LOCAL_ADDR}  ${PORT_NORMAL}
  ${ports} =  Create List  ${port_normal}
  Generic Teardown  @{ports}

Sync Fuzzy Storage
  [Arguments]  @{vargs}
  ${len} =  Get Length  ${vargs}
  ${result} =  Run Keyword If  $len == 0  Run Process  ${RSPAMADM}  control  -s  ${TMPDIR}/rspamd.sock  fuzzy_sync
  ...  ELSE  Run Process  ${RSPAMADM}  control  -s  @{vargs}[0]/rspamd.sock  fuzzy_sync
  Log  ${result.stdout}
  Run Keyword If  $len == 0  Follow Rspamd Log
  ...  ELSE  Custom Follow Rspamd Log  @{vargs}[0]/rspamd.log  @{vargs}[1]  @{vargs}[2]  @{vargs}[3]
  Sleep  0.1s  Try give fuzzy storage time to sync
