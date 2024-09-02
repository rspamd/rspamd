*** Settings ***
Library         Collections
Library         OperatingSystem
Library         Process

*** Keywords ***
Check Controller Errors
  @{result} =  HTTP  GET  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /errors
  Should Be Equal As Integers  ${result}[0]  200
  Log  ${result}[1]

Check Pidfile
  [Arguments]  ${pidfile}  ${timeout}=1 min
  Wait Until Created  ${pidfile}  timeout=${timeout}
  ${size} =  Get File Size  ${pidfile}
  Should Not Be Equal As Integers  ${size}  0

Check Rspamc
  [Arguments]  ${result}  @{args}  &{kwargs}
  IF  ${result.rc} != 0
    Log  ${result.stderr}
  END
  ${has_rc} =  Evaluate  'rc' in $kwargs
  ${inverse} =  Evaluate  'inverse' in $kwargs
  ${re} =  Evaluate  're' in $kwargs
  ${rc} =  Set Variable If  ${has_rc} == True  ${kwargs}[rc]  0
  FOR  ${i}  IN  @{args}
    IF  ${re} == True
      Check Rspamc Match Regexp  ${result.stdout}  ${i}  ${inverse}
    ELSE
      Check Rspamc Match String  ${result.stdout}  ${i}  ${inverse}
    END
  END
  IF  @{args} == @{EMPTY}
    Check Rspamc Match Default  ${result.stdout}  ${inverse}
  END
  Should Be Equal As Integers  ${result.rc}  ${rc}

Check Rspamc Match Default
  [Arguments]  ${subject}  ${inverse}
  IF  ${inverse} == False
    Should Contain  ${subject}  success = true
  ELSE
    Should Not Contain  ${subject}  success = true
  END

Check Rspamc Match Regexp
  [Arguments]  ${subject}  ${re}  ${inverse}
  IF  ${inverse} == False
    Should Match Regexp  ${subject}  ${re}
  ELSE
    Should Not Match Regexp ${subject}  ${re}
  END

Check Rspamc Match String
  [Arguments]  ${subject}  ${str}  ${inverse}
  IF  ${inverse} == False
    Should Contain  ${subject}  ${str}
  ELSE
    Should Not Contain  ${subject}  ${str}
  END

Do Not Expect Added Header
  [Arguments]  ${header_name}
  IF  'milter' not in ${SCAN_RESULT}
    RETURN
  END
  IF  'add_headers' not in ${SCAN_RESULT}[milter]
    RETURN
  END
  Dictionary Should Not Contain Key  ${SCAN_RESULT}[milter][add_headers]  ${header_name}
  ...  msg=${header_name} was added

Do Not Expect Removed Header
  [Arguments]  ${header_name}
  IF  'milter' not in ${SCAN_RESULT}
    RETURN
  END
  IF  'remove_headers' not in ${SCAN_RESULT}[milter]
    RETURN
  END
  Dictionary Should Not Contain Key  ${SCAN_RESULT}[milter][remove_headers]  ${header_name}
  ...  msg=${header_name} was removed

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

Expect Action
  [Arguments]  ${action}
  Should Be Equal  ${SCAN_RESULT}[action]  ${action}

Expect Added Header
  [Arguments]  ${header_name}  ${header_value}  ${pos}=-1
  Dictionary Should Contain Key  ${SCAN_RESULT}  milter
  ...  msg=milter block was not present in protocol response
  Dictionary Should Contain Key  ${SCAN_RESULT}[milter]  add_headers
  ...  msg=add_headers block was not present in protocol response
  Dictionary Should Contain Key  ${SCAN_RESULT}[milter][add_headers]  ${header_name}
  ...  msg=${header_name} was not added
  Should Be Equal  ${SCAN_RESULT}[milter][add_headers][${header_name}][value]  ${header_value}
  Should Be Equal as Numbers  ${SCAN_RESULT}[milter][add_headers][${header_name}][order]  ${pos}

Expect Email
  [Arguments]  ${email}
  List Should Contain Value  ${SCAN_RESULT}[emails]  ${email}

Expect Removed Header
  [Arguments]  ${header_name}  ${pos}=0
  Dictionary Should Contain Key  ${SCAN_RESULT}  milter
  ...  msg=milter block was not present in protocol response
  Dictionary Should Contain Key  ${SCAN_RESULT}[milter]  remove_headers
  ...  msg=remove_headers block was not present in protocol response
  Dictionary Should Contain Key  ${SCAN_RESULT}[milter][remove_headers]  ${header_name}
  ...  msg=${header_name} was not removed
  Should Be Equal as Numbers  ${SCAN_RESULT}[milter][remove_headers][${header_name}]  ${pos}

Expect Required Score
  [Arguments]  ${required_score}
  Should Be Equal As Numbers  ${SCAN_RESULT}[required_score]  ${required_score}

Expect Required Score To Be Null
  Should Be Equal  ${SCAN_RESULT}[required_score]  ${NONE}

Expect Score
  [Arguments]  ${score}
  Should Be Equal As Numbers  ${SCAN_RESULT}[score]  ${score}
  ...  msg="Expected message score of ${score} but got ${SCAN_RESULT}[score]"

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
  Lists Should Be Equal  ${have_options}  ${options}  ignore_order=True
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

Export Rspamd Variables To Environment
  &{all_vars} =  Get Variables  no_decoration=True
  FOR  ${k}  ${v}  IN  &{all_vars}
    IF  '${k}'.startswith("RSPAMD_")
      Set Environment Variable  ${k}  ${v}
    END
  END

Export Scoped Variables
  [Arguments]  ${scope}  &{vars}
  IF  '${scope}' == 'Test'
    FOR  ${k}  ${v}  IN  &{vars}
      Set Test Variable  ${${k}}  ${v}
    END
  ELSE IF  '${scope}' == 'Suite'
    FOR  ${k}  ${v}  IN  &{vars}
      Set Suite Variable  ${${k}}  ${v}
    END
  ELSE IF  '${scope}' == 'Global'
    FOR  ${k}  ${v}  IN  &{vars}
      Set Global Variable  ${${k}}  ${v}
    END
  ELSE
    Fail  message="Don't know what to do with scope: ${scope}"
  END

Log does not contain segfault record
  ${log} =  Get File  ${RSPAMD_TMPDIR}/rspamd.log  encoding_errors=ignore
  Should not contain  ${log}  (Segmentation fault)  msg=Segmentation fault detected

Redis HSET
  [Arguments]  ${hash}  ${key}  ${value}
  ${result} =  Run Process  redis-cli  -h  ${RSPAMD_REDIS_ADDR}  -p  ${RSPAMD_REDIS_PORT}
  ...  HSET  ${hash}  ${key}  ${value}
  IF  ${result.rc} != 0
    Log  ${result.stderr}
  END
  Log  ${result.stdout}
  Should Be Equal As Integers  ${result.rc}  0

Redis SET
  [Arguments]  ${key}  ${value}
  ${result} =  Run Process  redis-cli  -h  ${RSPAMD_REDIS_ADDR}  -p  ${RSPAMD_REDIS_PORT}
  ...  SET  ${key}  ${value}
  IF  ${result.rc} != 0
    Log  ${result.stderr}
  END
  Log  ${result.stdout}
  Should Be Equal As Integers  ${result.rc}  0

Redis Teardown
  Terminate Process  ${REDIS_PROCESS}
  Wait For Process  ${REDIS_PROCESS}
  Cleanup Temporary Directory  ${REDIS_TMPDIR}

Rspamd Setup
  [Arguments]  ${check_port}=${RSPAMD_PORT_NORMAL}
  # Create and chown temporary directory
  ${RSPAMD_TMPDIR} =  Make Temporary Directory
  Set Directory Ownership  ${RSPAMD_TMPDIR}  ${RSPAMD_USER}  ${RSPAMD_GROUP}

  # Export ${RSPAMD_TMPDIR} to appropriate scope according to ${RSPAMD_SCOPE}
  Export Scoped Variables  ${RSPAMD_SCOPE}  RSPAMD_TMPDIR=${RSPAMD_TMPDIR}

  Run Rspamd  check_port=${check_port}

Rspamd Redis Setup
  Run Redis
  Rspamd Setup

Rspamd Teardown
  IF  '${CONTROLLER_ERRORS}' == 'True'
    Run Keyword And Warn On Failure  Check Controller Errors
  END
  Terminate Process  ${RSPAMD_PROCESS}
  Wait For Process  ${RSPAMD_PROCESS}
  Save Run Results  ${RSPAMD_TMPDIR}  configdump.stdout configdump.stderr rspamd.stderr rspamd.stdout rspamd.conf rspamd.log redis.log clickhouse-config.xml
  Log does not contain segfault record
  Collect Lua Coverage
  Cleanup Temporary Directory  ${RSPAMD_TMPDIR}

Rspamd Redis Teardown
  Rspamd Teardown
  Redis Teardown

Run Redis
  ${RSPAMD_TMPDIR} =  Make Temporary Directory
  ${template} =  Get File  ${RSPAMD_TESTDIR}/configs/redis-server.conf
  ${config} =  Replace Variables  ${template}
  Create File  ${RSPAMD_TMPDIR}/redis-server.conf  ${config}
  Log  ${config}
  ${result} =  Start Process  redis-server  ${RSPAMD_TMPDIR}/redis-server.conf
  Wait Until Keyword Succeeds  5x  1 sec  Check Pidfile  ${RSPAMD_TMPDIR}/redis.pid  timeout=0.5s
  Wait Until Keyword Succeeds  5x  1 sec  Redis Check  ${RSPAMD_REDIS_ADDR}  ${RSPAMD_REDIS_PORT}
  ${REDIS_PID} =  Get File  ${RSPAMD_TMPDIR}/redis.pid
  ${REDIS_PID} =  Convert To Number  ${REDIS_PID}
  Export Scoped Variables  ${REDIS_SCOPE}  REDIS_PID=${REDIS_PID}  REDIS_PROCESS=${result}  REDIS_TMPDIR=${RSPAMD_TMPDIR}
  ${redis_log} =  Get File  ${RSPAMD_TMPDIR}/redis.log
  Log  ${redis_log}

Run Rspamd
  [Arguments]  ${check_port}=${RSPAMD_PORT_NORMAL}
  Export Rspamd Variables To Environment

  # Dump templated config or errors to log
  ${result} =  Run Process  ${RSPAMADM}
  ...  --var\=TMPDIR\=${RSPAMD_TMPDIR}
  ...  --var\=DBDIR\=${RSPAMD_TMPDIR}
  ...  --var\=LOCAL_CONFDIR\=/non-existent
  ...  --var\=CONFDIR\=${RSPAMD_TESTDIR}/../../conf/
  ...  configdump  -c  ${CONFIG}
  ...  env:RSPAMD_LOCAL_CONFDIR=/non-existent
  ...  env:RSPAMD_TMPDIR=${RSPAMD_TMPDIR}
  ...  env:RSPAMD_CONFDIR=${RSPAMD_TESTDIR}/../../conf/
  ...  env:LD_LIBRARY_PATH=${RSPAMD_TESTDIR}/../../contrib/aho-corasick
  ...  env:RSPAMD_NO_CLEANUP=1
  ...  env:ASAN_OPTIONS=quarantine_size_mb=2048:malloc_context_size=20:fast_unwind_on_malloc=0:log_path=${RSPAMD_TMPDIR}/rspamd-asan
  # We need to send output to files (or discard output) to avoid hanging Robot
  ...  stdout=${RSPAMD_TMPDIR}/configdump.stdout  stderr=${RSPAMD_TMPDIR}/configdump.stderr
  IF  ${result.rc} == 0
    ${configdump} =  Get File  ${RSPAMD_TMPDIR}/configdump.stdout  encoding_errors=ignore
  ELSE
    ${configdump} =  Get File  ${RSPAMD_TMPDIR}/configdump.stderr  encoding_errors=ignore
  END
  Log  ${configdump}

  # Fix directory ownership (maybe do this somewhere else)
  Set Directory Ownership  ${RSPAMD_TMPDIR}  ${RSPAMD_USER}  ${RSPAMD_GROUP}

  # Run Rspamd
  ${result} =  Start Process  ${RSPAMD}  -f  -u  ${RSPAMD_USER}  -g  ${RSPAMD_GROUP}
  ...  -c  ${CONFIG}
  ...  --var\=TMPDIR\=${RSPAMD_TMPDIR}
  ...  --var\=DBDIR\=${RSPAMD_TMPDIR}
  ...  --var\=LOCAL_CONFDIR\=/non-existent
  ...  --var\=CONFDIR\=${RSPAMD_TESTDIR}/../../conf/
  ...  --insecure
  ...  env:RSPAMD_LOCAL_CONFDIR=/non-existent
  ...  env:RSPAMD_TMPDIR=${RSPAMD_TMPDIR}
  ...  env:RSPAMD_CONFDIR=${RSPAMD_TESTDIR}/../../conf/
  ...  env:LD_LIBRARY_PATH=${RSPAMD_TESTDIR}/../../contrib/aho-corasick
  ...  env:RSPAMD_NO_CLEANUP=1
  ...  env:ASAN_OPTIONS=quarantine_size_mb=2048:malloc_context_size=20:fast_unwind_on_malloc=0:log_path=${RSPAMD_TMPDIR}/rspamd-asan
  ...  stdout=${RSPAMD_TMPDIR}/rspamd.stdout  stderr=${RSPAMD_TMPDIR}/rspamd.stderr

  Export Scoped Variables  ${RSPAMD_SCOPE}  RSPAMD_PROCESS=${result}

  # Confirm worker is reachable
  FOR    ${index}    IN RANGE    37
    ${ok} =  Rspamd Startup Check  ${check_port}
    IF  ${ok}  CONTINUE
    Sleep  0.4s
  END

Rspamd Startup Check
  [Arguments]  ${check_port}=${RSPAMD_PORT_NORMAL}
  ${handle} =  Get Process Object
  ${res} =  Evaluate  $handle.poll()
  IF  ${res} != None
    ${stderr} =  Get File  ${RSPAMD_TMPDIR}/rspamd.stderr
    Fail  Process Is Gone, stderr: ${stderr}
  END
  ${ping} =  Run Keyword And Return Status  Ping Rspamd  ${RSPAMD_LOCAL_ADDR}  ${check_port}
  [Return]  ${ping}

Rspamadm Setup
  ${RSPAMADM_TMPDIR} =  Make Temporary Directory
  Set Suite Variable  ${RSPAMADM_TMPDIR}

Rspamadm Teardown
  Cleanup Temporary Directory  ${RSPAMADM_TMPDIR}

Rspamadm
  [Arguments]  @{args}
  ${result} =  Run Process  ${RSPAMADM}
  ...  --var\=TMPDIR\=${RSPAMADM_TMPDIR}
  ...  --var\=DBDIR\=${RSPAMADM_TMPDIR}
  ...  --var\=LOCAL_CONFDIR\=/nonexistent
  ...  @{args}
  [Return]  ${result}

Run Nginx
  ${template} =  Get File  ${RSPAMD_TESTDIR}/configs/nginx.conf
  ${config} =  Replace Variables  ${template}
  Create File  ${RSPAMD_TMPDIR}/nginx.conf  ${config}
  Log  ${config}
  ${result} =  Run Process  nginx  -c  ${RSPAMD_TMPDIR}/nginx.conf
  IF  ${result.rc} != 0
    Log  ${result.stderr}
  END
  Should Be Equal As Integers  ${result.rc}  0
  Wait Until Keyword Succeeds  10x  1 sec  Check Pidfile  ${RSPAMD_TMPDIR}/nginx.pid  timeout=0.5s
  Wait Until Keyword Succeeds  5x  1 sec  TCP Connect  ${NGINX_ADDR}  ${NGINX_PORT}
  ${NGINX_PID} =  Get File  ${RSPAMD_TMPDIR}/nginx.pid
  IF  '${NGINX_SCOPE}' == 'Test'
    Set Test Variable  ${NGINX_PID}
  ELSE IF  '${NGINX_SCOPE}' == 'Suite'
    Set Suite Variable  ${NGINX_PID}
  END
  ${nginx_log} =  Get File  ${RSPAMD_TMPDIR}/nginx.log
  Log  ${nginx_log}

Run Rspamc
  [Arguments]  @{args}
  ${result} =  Run Process  ${RSPAMC}  -t  60  --header  Queue-ID\=${TEST NAME}
  ...  @{args}  env:LD_LIBRARY_PATH=${RSPAMD_TESTDIR}/../../contrib/aho-corasick
  Log  ${result.stdout}
  [Return]  ${result}

Scan File By Reference
  [Arguments]  ${filename}  &{headers}
  Set To Dictionary  ${headers}  File=${filename}
  ${result} =  Scan File  /dev/null  &{headers}
  [Return]  ${result}

Scan Message With Rspamc
  [Arguments]  ${msg_file}  @{vargs}
  ${result} =  Run Rspamc  -p  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_NORMAL}  @{vargs}  ${msg_file}
  [Return]  ${result}

Sync Fuzzy Storage
  [Arguments]  @{vargs}
  ${len} =  Get Length  ${vargs}
  IF  $len == 0
    ${result} =  Run Process  ${RSPAMADM}  control  -s
    ...  ${RSPAMD_TMPDIR}/rspamd.sock  fuzzy_sync
  ELSE
    Run Process  ${RSPAMADM}  control  -s  ${vargs}[0]/rspamd.sock
    ...  fuzzy_sync
  END
  Log  ${result.stdout}
  Sleep  0.1s  Try give fuzzy storage time to sync

Run Dummy Http
  ${result} =  Start Process  ${RSPAMD_TESTDIR}/util/dummy_http.py  -pf  /tmp/dummy_http.pid
  Wait Until Created  /tmp/dummy_http.pid  timeout=2 second
  Export Scoped Variables  ${RSPAMD_SCOPE}  DUMMY_HTTP_PROC=${result}

Run Dummy Https
  ${result} =  Start Process  ${RSPAMD_TESTDIR}/util/dummy_http.py
  ...  -c  ${RSPAMD_TESTDIR}/util/server.pem  -k  ${RSPAMD_TESTDIR}/util/server.pem
  ...  -pf  /tmp/dummy_https.pid  -p  18081
  Wait Until Created  /tmp/dummy_https.pid  timeout=2 second
  Export Scoped Variables  ${RSPAMD_SCOPE}  DUMMY_HTTPS_PROC=${result}

Dummy Http Teardown
  Terminate Process  ${DUMMY_HTTP_PROC}
  Wait For Process  ${DUMMY_HTTP_PROC}

Dummy Https Teardown
  Terminate Process  ${DUMMY_HTTPS_PROC}
  Wait For Process  ${DUMMY_HTTPS_PROC}
