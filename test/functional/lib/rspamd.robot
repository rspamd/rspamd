*** Settings ***
Library         Collections
Library         OperatingSystem
Library         Process

*** Keywords ***
Check Controller Errors
  @{result} =  HTTP  GET  ${LOCAL_ADDR}  ${PORT_CONTROLLER}  /errors
  Should Be Equal As Integers  ${result}[0]  200
  Log  ${result}[1]

Check Pidfile
  [Arguments]  ${pidfile}  ${timeout}=1 min
  Wait Until Created  ${pidfile}  timeout=${timeout}
  ${size} =  Get File Size  ${pidfile}
  Should Not Be Equal As Integers  ${size}  0

Check Rspamc
  [Arguments]  ${result}  @{args}  &{kwargs}
  Run Keyword If  ${result.rc} != 0  Log  ${result.stderr}
  ${has_rc} =  Evaluate  'rc' in $kwargs
  ${inverse} =  Evaluate  'inverse' in $kwargs
  ${re} =  Evaluate  're' in $kwargs
  ${rc} =  Set Variable If  ${has_rc} == True  ${kwargs}[rc]  0
  FOR  ${i}  IN  @{args}
    Run Keyword If  ${re} == True  Check Rspamc Match Regexp  ${result.stdout}  ${i}  ${inverse}
    ...  ELSE  Check Rspamc Match String  ${result.stdout}  ${i}  ${inverse}
  END
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

Do Not Expect Symbol
  [Arguments]  ${symbol}
  Dictionary Should Not Contain Key  ${SCAN_RESULT}[symbols]  ${symbol}
  ...  msg=Symbol ${symbol} was not expected to be found in result

Do Not Expect Symbols
  [Arguments]  @{symbols}
  FOR  ${symbol}  IN  @{symbols}
    Dictionary Should Not Contain Key  ${SCAN_RESULT}[symbols]  ${symbol}
    ...  msg=Symbol ${symbol} was not expected to be found in result
  END

Generic Setup
  [Arguments]  @{vargs}  &{kwargs}
  &{d} =  Run Rspamd  @{vargs}  &{kwargs}
  ${keys} =  Get Dictionary Keys  ${d}
  FOR  ${i}  IN  @{keys}
    Run Keyword If  '${RSPAMD_SCOPE}' == 'Suite'  Set Suite Variable  ${${i}}  ${d}[${i}]
    ...  ELSE IF  '${RSPAMD_SCOPE}' == 'Test'  Set Test Variable  ${${i}}  ${d}[${i}]
    ...  ELSE  Fail  'RSPAMD_SCOPE must be Test or Suite'
  END

Expect Action
  [Arguments]  ${action}
  Should Be Equal  ${SCAN_RESULT}[action]  ${action}

Expect Email
  [Arguments]  ${email}
  List Should Contain Value  ${SCAN_RESULT}[emails]  ${email}

Expect Required Score
  [Arguments]  ${required_score}
  Should Be Equal As Numbers  ${SCAN_RESULT}[required_score]  ${required_score}

Expect Required Score To Be Null
  Should Be Equal  ${SCAN_RESULT}[required_score]  ${NONE}

Expect Score
  [Arguments]  ${score}
  Should Be Equal As Numbers  ${SCAN_RESULT}[score]  ${score}

Expect Symbol
  [Arguments]  ${symbol}
  Dictionary Should Contain Key  ${SCAN_RESULT}[symbols]  ${symbol}
  ...  msg=Symbol ${symbol} wasn't found in result

Expect URL
  [Arguments]  ${url}
  List Should Contain Value  ${SCAN_RESULT}[urls]  ${url}

Expect Symbol With Exact Options
  [Arguments]  ${symbol}  @{options}
  Expect Symbol  ${symbol}
  ${have_options} =  Convert To List  ${SCAN_RESULT}[symbols][${symbol}][options]
  Lists Should Be Equal  ${have_options}  ${options}
  ...  msg="Symbol ${symbol} has options ${SCAN_RESULT}[symbols][${symbol}][options] but expected ${options}"

Expect Symbol With Option
  [Arguments]  ${symbol}  ${option}
  Expect Symbol  ${symbol}
  ${have_options} =  Convert To List  ${SCAN_RESULT}[symbols][${symbol}][options]
  Should Contain  ${have_options}  ${option}
  ...  msg="Options for symbol ${symbol} ${SCAN_RESULT}[symbols][${symbol}][options] doesn't contain ${option}"

Expect Symbol With Score
  [Arguments]  ${symbol}  ${score}
  Dictionary Should Contain Key  ${SCAN_RESULT}[symbols]  ${symbol}
  ...  msg=Symbol ${symbol} wasn't found in result
  Should Be Equal As Numbers  ${SCAN_RESULT}[symbols][${symbol}][score]  ${score}
  ...  msg="Symbol ${symbol} has score of ${SCAN_RESULT}[symbols][${symbol}][score] but expected ${score}"

Expect Symbols With Scores
  [Arguments]  &{symscores}
  FOR  ${key}  ${value}  IN  &{symscores}
    Dictionary Should Contain Key  ${SCAN_RESULT}[symbols]  ${key}
    ...  msg=Symbol ${key} wasn't found in result
    Should Be Equal As Numbers  ${SCAN_RESULT}[symbols][${key}][score]  ${value}
    ...  msg="Symbol ${key} has score of ${SCAN_RESULT}[symbols][${key}][score] but expected ${value}"
  END

Expect Symbol With Score And Exact Options
  [Arguments]  ${symbol}  ${score}  @{options}
  Expect Symbol With Exact Options  ${symbol}  @{options}
  Expect Symbol With Score  ${symbol}  ${score}

Generic Teardown
  Run Keyword If  '${CONTROLLER_ERRORS}' == 'True'  Check Controller Errors
  Shutdown Process With Children  ${RSPAMD_PID}
  Save Run Results  ${TMPDIR}  rspamd.conf rspamd.log redis.log clickhouse-config.xml
  Log does not contain segfault record
  Collect Lua Coverage
  Cleanup Temporary Directory  ${TMPDIR}

Log does not contain segfault record
  ${log} =  Get File  ${TMPDIR}/rspamd.log  encoding_errors=ignore
  Should not contain  ${log}  Segmentation fault:  msg=Segmentation fault detected

Normal Teardown
  Generic Teardown

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
  ${template} =  Get File  ${TESTDIR}/configs/redis-server.conf
  ${config} =  Replace Variables  ${template}
  Create File  ${TMPDIR}/redis-server.conf  ${config}
  Log  ${config}
  ${result} =  Run Process  redis-server  ${TMPDIR}/redis-server.conf
  Run Keyword If  ${result.rc} != 0  Log  ${result.stderr}
  Should Be Equal As Integers  ${result.rc}  0
  Wait Until Keyword Succeeds  5x  1 sec  Check Pidfile  ${TMPDIR}/redis.pid  timeout=0.5s
  Wait Until Keyword Succeeds  5x  1 sec  Redis Check  ${REDIS_ADDR}  ${REDIS_PORT}
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
  Wait Until Keyword Succeeds  10x  1 sec  Check Pidfile  ${TMPDIR}/nginx.pid  timeout=0.5s
  Wait Until Keyword Succeeds  5x  1 sec  TCP Connect  ${NGINX_ADDR}  ${NGINX_PORT}
  ${NGINX_PID} =  Get File  ${TMPDIR}/nginx.pid
  Run Keyword If  '${NGINX_SCOPE}' == 'Test'  Set Test Variable  ${NGINX_PID}
  ...  ELSE IF  '${NGINX_SCOPE}' == 'Suite'  Set Suite Variable  ${NGINX_PID}
  ${nginx_log} =  Get File  ${TMPDIR}/nginx.log
  Log  ${nginx_log}

Run Rspamc
  [Arguments]  @{args}
  ${result} =  Run Process  ${RSPAMC}  -t  60  --header  Queue-ID\=${TEST NAME}
  ...  @{args}  env:LD_LIBRARY_PATH=${TESTDIR}/../../contrib/aho-corasick
  Log  ${result.stdout}
  [Return]  ${result}

Run Rspamd
  [Arguments]  @{vargs}  &{kwargs}
  ${has_CONFIG} =  Evaluate  'CONFIG' in $kwargs
  ${has_TMPDIR} =  Evaluate  'TMPDIR' in $kwargs
  ${CONFIG} =  Set Variable If  '${has_CONFIG}' == 'True'  ${kwargs}[CONFIG]  ${CONFIG}
  &{d} =  Create Dictionary
  ${tmpdir} =  Run Keyword If  '${has_TMPDIR}' == 'True'  Set Variable  ${kwargs}[TMPDIR]
  ...  ELSE  Make Temporary Directory
  Set Directory Ownership  ${tmpdir}  ${RSPAMD_USER}  ${RSPAMD_GROUP}
  ${template} =  Get File  ${CONFIG}
  FOR  ${i}  IN  @{vargs}
    ${newvalue} =  Replace Variables  ${${i}}
    Set To Dictionary  ${d}  ${i}=${newvalue}
  END
  ${config} =  Replace Variables  ${template}
  ${config} =  Replace Variables  ${config}
  Log  ${config}
  Create File  ${tmpdir}/rspamd.conf  ${config}
  ${result} =  Run Process  ${RSPAMD}  -u  ${RSPAMD_USER}  -g  ${RSPAMD_GROUP}
  ...  -c  ${tmpdir}/rspamd.conf  env:TMPDIR=${tmpdir}  env:DBDIR=${tmpdir}  env:LD_LIBRARY_PATH=${TESTDIR}/../../contrib/aho-corasick
  Run Keyword If  ${result.rc} != 0  Log  ${result.stderr}
  Should Be Equal As Integers  ${result.rc}  0
  Wait Until Keyword Succeeds  10x  1 sec  Check Pidfile  ${tmpdir}/rspamd.pid  timeout=0.5s
  Wait Until Keyword Succeeds  5x  1 sec  Ping Rspamd  ${LOCAL_ADDR}  ${PORT_NORMAL}
  ${rspamd_pid} =  Get File  ${tmpdir}/rspamd.pid
  Set To Dictionary  ${d}  RSPAMD_PID=${rspamd_pid}  TMPDIR=${tmpdir}
  [Return]  &{d}

Simple Teardown
  Generic Teardown

Scan File By Reference
  [Arguments]  ${filename}  &{headers}
  Set To Dictionary  ${headers}  File=${filename}
  ${result} =  Scan File  /dev/null  &{headers}
  [Return]  ${result}

Scan Message With Rspamc
  [Arguments]  ${msg_file}  @{vargs}
  ${result} =  Run Rspamc  -p  -h  ${LOCAL_ADDR}:${PORT_NORMAL}  @{vargs}  ${msg_file}
  [Return]  ${result}

Sync Fuzzy Storage
  [Arguments]  @{vargs}
  ${len} =  Get Length  ${vargs}
  ${result} =  Run Keyword If  $len == 0  Run Process  ${RSPAMADM}  control  -s
  ...  ${TMPDIR}/rspamd.sock  fuzzy_sync
  ...  ELSE  Run Process  ${RSPAMADM}  control  -s  ${vargs}[0]/rspamd.sock
  ...  fuzzy_sync
  Log  ${result.stdout}
  Sleep  0.1s  Try give fuzzy storage time to sync
