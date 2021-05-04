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
  [Arguments]  &{kw}
  New Setup  &{kw}

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

Expect Extended URL
  [Arguments]  ${url}
  ${found_url} =  Set Variable  ${FALSE}
  ${url_list} =  Convert To List  ${SCAN_RESULT}[urls]
  FOR  ${item}  IN  @{url_list}
    ${d} =  Convert To Dictionary  ${item}
    ${found_url} =  Evaluate  "${d}[url]" == "${url}"
    Exit For Loop If  ${found_url} == ${TRUE}
  END
  Should Be True  ${found_url}  msg="Expected URL was not found: ${url}"

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

Expect Symbols
  [Arguments]  @{symbols}
  FOR  ${symbol}  IN  @{symbols}
    Dictionary Should Contain Key  ${SCAN_RESULT}[symbols]  ${symbol}
    ...  msg=Symbol ${symbol} wasn't found in result
  END

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

Export Scoped Variables
  [Arguments]  ${scope}  &{vars}
  FOR  ${k}  ${v}  IN  &{vars}
    Run Keyword If  '${scope}' == 'Test'  Set Test Variable  ${${k}}  ${v}
    ...  ELSE IF  '${scope}' == 'Suite'  Set Suite Variable  ${${k}}  ${v}
    ...  ELSE IF  '${scope}' == 'Global'  Set Global Variable  ${${k}}  ${v}
    ...  ELSE  Fail  message="Don't know what to do with scope: ${scope}"
  END

Generic Teardown
  # Robot Framework 4.0
  #Run Keyword If  '${CONTROLLER_ERRORS}' == 'True'  Run Keyword And Warn On Failure  Check Controller Errors
  Run Keyword If  '${CONTROLLER_ERRORS}' == 'True'  Check Controller Errors
  Shutdown Process With Children  ${RSPAMD_PID}
  Save Run Results  ${TMPDIR}  rspamd.conf rspamd.log redis.log clickhouse-config.xml
  Log does not contain segfault record
  Collect Lua Coverage
  Cleanup Temporary Directory  ${TMPDIR}

  # Possibly deal with Redis
  ${redis_tmpdir} =  Get Variable Value  ${REDIS_TMPDIR}
  Run Keyword If  '${redis_tmpdir}' != 'None'  Cleanup Temporary Directory  ${REDIS_TMPDIR}
  ${redis_pid} =  Get Variable Value  ${REDIS_PID}
  Run Keyword If  '${redis_pid}' == 'None'  Return From Keyword
  Shutdown Process With Children  ${redis_pid}

Log does not contain segfault record
  ${log} =  Get File  ${TMPDIR}/rspamd.log  encoding_errors=ignore
  Should not contain  ${log}  Segmentation fault:  msg=Segmentation fault detected

New Setup
  [Arguments]  &{kw}

  # Create and chown temporary directory
  ${TMPDIR} =  Make Temporary Directory
  Set Directory Ownership  ${TMPDIR}  ${RSPAMD_USER}  ${RSPAMD_GROUP}

  # Export ${TMPDIR} to appropriate scope according to ${RSPAMD_SCOPE}
  Export Scoped Variables  ${RSPAMD_SCOPE}  TMPDIR=${TMPDIR}

  # Set additional values to ${kw} that are expected to be available everywhere
  Set To Dictionary  ${kw}  LOCAL_ADDR=${LOCAL_ADDR}  PORT_NORMAL=${PORT_NORMAL}
  ...  KEY_PUB1=${KEY_PUB1}  KEY_PVT1=${KEY_PVT1}  PORT_CONTROLLER=${PORT_CONTROLLER}
  ...  TESTDIR=${TESTDIR}  INSTALLROOT=${INSTALLROOT}  TMPDIR=${TMPDIR}
  ...  MAP_WATCH_INTERVAL=${MAP_WATCH_INTERVAL}  PORT_PROXY=${PORT_PROXY}

  New Run Rspamd  &{kw}

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
  ${TMPDIR} =  Make Temporary Directory
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
  ${REDIS_PID} =  Convert To Number  ${REDIS_PID}
  Export Scoped Variables  ${REDIS_SCOPE}  REDIS_PID=${REDIS_PID}  REDIS_TMPDIR=${TMPDIR}
  ${redis_log} =  Get File  ${TMPDIR}/redis.log
  Log  ${redis_log}

Run Rspamd
  [Arguments]  &{kwargs}
  New Run Rspamd  &{kwargs}

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

New Run Rspamd
  [Arguments]  &{kwargs}

  # Set each kwarg to environment variable prefixed with RSPAMD_
  FOR  ${k}  ${v}  IN  &{kwargs}
    Set Environment Variable  RSPAMD_${k}  ${v}
  END

  # Dump templated config or errors to log
  ${result} =  Run Process  ${RSPAMADM}  configdump  -c  ${CONFIG}
  # We need to send output to files (or discard output) to avoid hanging Robot
  ...  stdout=${TMPDIR}/configdump.stdout  stderr=${TMPDIR}/configdump.stderr
  ${configdump} =  Run Keyword If  ${result.rc} == 0  Get File  ${TMPDIR}/configdump.stdout
  ...  ELSE  Get File  ${TMPDIR}/configdump.stderr
  Log  ${configdump}

  # Fix directory ownership (maybe do this somewhere else)
  Set Directory Ownership  ${TMPDIR}  ${RSPAMD_USER}  ${RSPAMD_GROUP}

  # Run Rspamd
  ${result} =  Run Process  ${RSPAMD}  -u  ${RSPAMD_USER}  -g  ${RSPAMD_GROUP}
  ...  -c  ${CONFIG}  env:TMPDIR=${TMPDIR}  env:DBDIR=${TMPDIR}  env:LD_LIBRARY_PATH=${TESTDIR}/../../contrib/aho-corasick
  ...  env:RSPAMD_INSTALLROOT=${INSTALLROOT}  env:RSPAMD_TMPDIR=${TMPDIR}  env:RSPAMD_TESTDIR=${TESTDIR}
  # We need to send output to files (or discard output) to avoid hanging Robot
  ...  stdout=${TMPDIR}/rspamd.stdout  stderr=${TMPDIR}/rspamd.stderr

  # Abort if it failed
  Should Be Equal As Integers  ${result.rc}  0

  # Wait for pid file to be written
  Wait Until Keyword Succeeds  10x  1 sec  Check Pidfile  ${TMPDIR}/rspamd.pid  timeout=0.5s

  # Confirm worker is reachable
  Wait Until Keyword Succeeds  5x  1 sec  Ping Rspamd  ${LOCAL_ADDR}  ${PORT_NORMAL}

  # Read PID from PIDfile and export it to appropriate scope as ${RSPAMD_PID}
  ${RSPAMD_PID} =  Get File  ${TMPDIR}/rspamd.pid
  Export Scoped Variables  ${RSPAMD_SCOPE}  RSPAMD_PID=${RSPAMD_PID}

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
