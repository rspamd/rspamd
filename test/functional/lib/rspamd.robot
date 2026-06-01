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

Do Not Expect Symbol With Option
  [Arguments]  ${symbol}  ${option}
  IF  '${symbol}' not in ${SCAN_RESULT}[symbols]
    RETURN
  END
  ${have_options} =  Convert To List  ${SCAN_RESULT}[symbols][${symbol}][options]
  Should Not Contain  ${have_options}  ${option}
  ...  msg="Options for symbol ${symbol} ${SCAN_RESULT}[symbols][${symbol}][options] doesn't contain ${option}"

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
  Dictionary Should Contain Key  ${SCAN_RESULT}[milter][add_headers][${header_name}]  value
  ...  msg=no value field in ${header_name} index: ${SCAN_RESULT}[milter][add_headers][${header_name}]
  Should Be Equal  ${SCAN_RESULT}[milter][add_headers][${header_name}][value]  ${header_value}
  Should Be Equal as Numbers  ${SCAN_RESULT}[milter][add_headers][${header_name}][order]  ${pos}

Expect Header Is Present
  [Arguments]  ${header_name}
  Dictionary Should Contain Key  ${SCAN_RESULT}  milter
  ...  msg=milter block was not present in protocol response
  Dictionary Should Contain Key  ${SCAN_RESULT}[milter]  add_headers
  ...  msg=add_headers block was not present in protocol response
  Dictionary Should Contain Key  ${SCAN_RESULT}[milter][add_headers]  ${header_name}
  ...  msg=${header_name} was not added

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

Do Not Expect Extended URL
  [Arguments]  ${url}
  ${found_url} =  Set Variable  ${FALSE}
  ${url_list} =  Convert To List  ${SCAN_RESULT}[urls]
  FOR  ${item}  IN  @{url_list}
    ${d} =  Convert To Dictionary  ${item}
    ${found_url} =  Evaluate  "${d}[url]" == "${url}"
    Exit For Loop If  ${found_url} == ${TRUE}
  END
  Should Not Be True  ${found_url}  msg="URL should not be present: ${url}"

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
  IF  '${RSPAMD_SCOPE}' == 'Test'
    Set Test Variable  ${RSPAMD_TMPDIR}
  ELSE IF  '${RSPAMD_SCOPE}' == 'Suite'
    Set Suite Variable  ${RSPAMD_TMPDIR}
    # Needed for child suites (e.g. directory suites with per-file .robot suites)
    Set Global Variable  ${RSPAMD_TMPDIR}
  ELSE IF  '${RSPAMD_SCOPE}' == 'Global'
    Set Global Variable  ${RSPAMD_TMPDIR}
  ELSE
    Fail  message="Don't know what to do with scope: ${RSPAMD_SCOPE}"
  END

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

  # Copy config file to TMPDIR so it gets saved on teardown
  Copy File  ${CONFIG}  ${RSPAMD_TMPDIR}/rspamd.conf

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

  # Always save configdump output to files, even if it failed
  # First save process output directly to ensure we have something even if files weren't created
  ${stdout_exists} =  Run Keyword And Return Status  File Should Exist  ${RSPAMD_TMPDIR}/configdump.stdout
  ${stderr_exists} =  Run Keyword And Return Status  File Should Exist  ${RSPAMD_TMPDIR}/configdump.stderr

  IF  not ${stdout_exists}
    # File wasn't created, use process stdout if available
    ${stdout_len} =  Get Length  ${result.stdout}
    IF  ${stdout_len} > 0
      Create File  ${RSPAMD_TMPDIR}/configdump.stdout  ${result.stdout}
    ELSE
      Create File  ${RSPAMD_TMPDIR}/configdump.stdout  <configdump stdout not created, process crashed?>
    END
  END

  IF  not ${stderr_exists}
    # File wasn't created, use process stderr if available
    ${stderr_len} =  Get Length  ${result.stderr}
    IF  ${stderr_len} > 0
      Create File  ${RSPAMD_TMPDIR}/configdump.stderr  ${result.stderr}
    ELSE
      Create File  ${RSPAMD_TMPDIR}/configdump.stderr  <configdump stderr not created, process crashed?>
    END
  END

  IF  ${result.rc} == 0
    ${configdump} =  Get File  ${RSPAMD_TMPDIR}/configdump.stdout  encoding_errors=ignore
  ELSE
    ${configdump} =  Get File  ${RSPAMD_TMPDIR}/configdump.stderr  encoding_errors=ignore
    Log  Configdump failed with rc=${result.rc}  level=WARN
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

  # Confirm worker is reachable. The original loop used CONTINUE on
  # success, which meant it kept polling for the full 37 iterations
  # even after the first successful ping. Break on success so the
  # caller sees a tight startup.
  FOR    ${index}    IN RANGE    37
    ${ok} =  Rspamd Startup Check  ${check_port}
    IF  ${ok}    BREAK
    Sleep  0.4s
  END
  # rspamd ping succeeds as soon as the controller binds its HTTP
  # socket, but for suites whose config includes options.inc the
  # main process also creates a unix control socket at
  # $DBDIR/rspamd.sock, and the workers list isn't populated there
  # until each worker has registered back with main. Under parallel
  # pabot + concurrent serial robot that gap can stretch out and
  # the first `rspamadm control stat` in 099_control returns empty.
  #
  # If the suite's config produces a control socket, wait until
  # `rspamadm control stat` actually contains "workers" before
  # letting tests run. If it never does (minimal configs without
  # options.inc), proceed without the extra check -- those suites
  # don't talk to the control socket anyway.
  ${sock_path} =  Set Variable  ${RSPAMD_TMPDIR}/rspamd.sock
  ${sock_ready} =  Run Keyword And Return Status
  ...    Wait Until Created  ${sock_path}  timeout=2s
  IF    ${sock_ready}
    Wait Until Keyword Succeeds  30x  0.2s  Verify Controller Workers Registered  ${sock_path}
  END

Verify Controller Workers Registered
  [Documentation]  Used by Run Rspamd to wait until the controller
  ...              has published its workers list to the local
  ...              control socket. Cheap when fast, retried up to
  ...              ~6s when rspamd is starting under CPU contention
  ...              (4 pabot workers + concurrent serial robot).
  [Arguments]  ${sock}
  ${result} =  Run Process  ${RSPAMADM}  control  -s  ${sock}  stat  timeout=2s
  Should Be Equal As Integers  ${result.rc}  0
  Should Contain  ${result.stdout}  workers

Rspamd Startup Check
  [Arguments]  ${check_port}=${RSPAMD_PORT_NORMAL}
  ${handle} =  Get Process Object
  ${res} =  Evaluate  $handle.poll()
  IF  ${res} != None
    # rspamd exited; rspamd.stderr typically only has the early
    # "loading configuration" line because the real logger is set up
    # later. The actual cause lives in rspamd.log -- include both and
    # the exit code so failures aren't just opaque.
    ${stderr} =  Get File  ${RSPAMD_TMPDIR}/rspamd.stderr  encoding_errors=ignore
    ${log_exists} =  Run Keyword And Return Status  File Should Exist  ${RSPAMD_TMPDIR}/rspamd.log
    IF  ${log_exists}
      ${log_full} =  Get File  ${RSPAMD_TMPDIR}/rspamd.log  encoding_errors=ignore
      ${log_tail} =  Evaluate  "\\n".join($log_full.splitlines()[-80:])
    ELSE
      ${log_tail} =  Set Variable  <rspamd.log was never created>
    END
    Fail  Process Is Gone (rc=${res}, port=${check_port}, tmpdir=${RSPAMD_TMPDIR})\n--- stderr ---\n${stderr}\n--- rspamd.log (tail) ---\n${log_tail}
  END
  ${ping} =  Run Keyword And Return Status  Ping Rspamd  ${RSPAMD_LOCAL_ADDR}  ${check_port}
  RETURN    ${ping}

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
  RETURN    ${result}

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

Set Test Hash Documentation
  ${log_tag} =  Evaluate  __import__('hashlib').md5('${TEST NAME}'.encode()).hexdigest()[:8]
  Log    TEST CONTEXT: [${log_tag}] ${TEST NAME}    console=True

Run Rspamc
  [Arguments]  @{args}
  ${log_tag} =  Evaluate  __import__('hashlib').md5('${TEST NAME}'.encode()).hexdigest()[:8]
  # Check if --queue-id is already provided in the arguments
  ${args_str} =  Evaluate  ' '.join(@{args})
  ${has_queue_id} =  Evaluate  '--queue-id' in '${args_str}'
  IF  ${has_queue_id}
    ${result} =  Run Process  ${RSPAMC}  -t  60  --log-tag  ${log_tag}
    ...  @{args}  env:LD_LIBRARY_PATH=${RSPAMD_TESTDIR}/../../contrib/aho-corasick
  ELSE
    ${result} =  Run Process  ${RSPAMC}  -t  60  --queue-id  ${TEST NAME}  --log-tag  ${log_tag}
    ...  @{args}  env:LD_LIBRARY_PATH=${RSPAMD_TESTDIR}/../../contrib/aho-corasick
  END
  Log  ${result.stdout}
  RETURN    ${result}

Render Message Template
  [Documentation]  Read an .eml fixture that contains Robot ${VARIABLE}
  ...  placeholders (e.g. ${RSPAMD_PORT_DUMMY_HTTP}), expand them, write
  ...  the result into the suite tmpdir and return the rendered path.
  ...  .eml files are fed raw to the scanner and are NOT processed by the
  ...  config-time Jinja engine, so per-pabot-worker values (dummy ports)
  ...  must be substituted here at runtime. Requires ${RSPAMD_TMPDIR}
  ...  (set by Rspamd Setup) -- call after the rspamd setup keyword.
  [Arguments]  ${template_path}
  ${template} =  Get File  ${template_path}
  ${rendered} =  Replace Variables  ${template}
  ${name} =  Evaluate  os.path.basename($template_path)  modules=os
  ${out} =  Set Variable  ${RSPAMD_TMPDIR}/${name}
  Create File  ${out}  ${rendered}
  RETURN  ${out}

Scan File By Reference
  [Arguments]  ${filename}  &{headers}
  Set To Dictionary  ${headers}  File=${filename}
  ${result} =  Scan File  /dev/null  &{headers}
  RETURN    ${result}

Scan Message With Rspamc
  [Arguments]  ${msg_file}  @{vargs}
  ${result} =  Run Rspamc  -p  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_NORMAL}  @{vargs}  ${msg_file}
  RETURN    ${result}

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

Run Control Command
  [Documentation]  Run a control socket command and return the result
  [Arguments]  ${command}  ${socket}
  ${result} =  Run Process  ${RSPAMADM}  control  -s
  ...  ${socket}  ${command}  timeout=10s
  Log  ${result.stdout}
  Log  ${result.stderr}
  RETURN    ${result}

Run Control Command JSON
  [Documentation]  Run a control socket command and return JSON result
  [Arguments]  ${command}  ${socket}
  ${result} =  Run Process  ${RSPAMADM}  control  -j  -s
  ...  ${socket}  ${command}  timeout=10s
  Log  ${result.stdout}
  Log  ${result.stderr}
  RETURN    ${result}

Start Dummy Service
  [Documentation]  Start a dummy_* helper and block until it is ready,
  ...  then return its process handle. Readiness is the PID file: every
  ...  dummy_* helper calls dummy_killer.write_pid() only AFTER it has
  ...  bound and activated its listening socket (see server_bind /
  ...  server_activate / server.start in util/dummy_*.py), so the moment
  ...  the PID file appears the kernel is already accepting connections.
  ...  This keyword is the ONE place that barrier lives -- start every
  ...  dummy through here (or a Run Dummy * / Start Dummy * wrapper),
  ...  never via a bare Start Process followed straight by a scan, or you
  ...  reintroduce the start/scan race that flakes under parallel pabot.
  [Arguments]  ${name}  ${pidfile}  ${logfile}  @{command}
  # Drop any stale PID file from a previous instance on this same path.
  # One-shot helpers (clam/fprot/avast/p0f) exit after a single request
  # and leave their PID file behind; without this a same-port restart
  # would satisfy Wait Until Created instantly and race the new bind.
  Remove File  ${pidfile}
  ${result} =  Start Process  @{command}  stdout=${logfile}  stderr=${logfile}
  ${status}  ${error} =  Run Keyword And Ignore Error
  ...  Wait Until Created  ${pidfile}  timeout=5 second
  IF  '${status}' == 'FAIL'
    ${logstatus}  ${out} =  Run Keyword And Ignore Error  Get File  ${logfile}
    IF  '${logstatus}' == 'PASS'
      Log  ${name} failed to start. Log output:\n${out}  level=ERROR
    ELSE
      Log  ${name} failed to start. No log file found at ${logfile}  level=ERROR
    END
    Fail  ${name} did not create PID file in 5 seconds
  END
  RETURN  ${result}

Wait Until Dummy Listening
  [Documentation]  Belt-and-suspenders readiness probe on top of the PID
  ...  barrier: block until a TCP connect to host:port actually succeeds.
  ...  Self-contained (BuiltIn Evaluate, no library dependency). Use ONLY
  ...  for helpers that loop and accept many connections (http/https/ssl).
  ...  Do NOT probe one-shot helpers (clam/fprot/avast/p0f) or the
  ...  single-threaded smtp helper -- a probe connection would consume or
  ...  block the very session the scan needs; for those the PID barrier in
  ...  Start Dummy Service is the correct and sufficient readiness signal.
  [Arguments]  ${host}  ${port}
  Wait Until Keyword Succeeds  15x  0.2s
  ...  Evaluate  __import__('socket').create_connection(("${host}", ${port}), 1).close()

Run Dummy Http
  ${pid} =  Set Variable  ${RSPAMD_TMP_PREFIX}/dummy_http-${RSPAMD_PORT_DUMMY_HTTP}.pid
  ${log} =  Set Variable  ${RSPAMD_TMP_PREFIX}/dummy_http-${RSPAMD_PORT_DUMMY_HTTP}.log
  ${result} =  Start Dummy Service  dummy_http.py  ${pid}  ${log}
  ...  ${RSPAMD_TESTDIR}/util/dummy_http.py  -pf  ${pid}  -p  ${RSPAMD_PORT_DUMMY_HTTP}
  Wait Until Dummy Listening  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_DUMMY_HTTP}
  Export Scoped Variables  ${RSPAMD_SCOPE}  DUMMY_HTTP_PROC=${result}  DUMMY_HTTP_LOG=${log}

Run Dummy Https
  ${pid} =  Set Variable  ${RSPAMD_TMP_PREFIX}/dummy_https-${RSPAMD_PORT_DUMMY_HTTPS}.pid
  ${log} =  Set Variable  ${RSPAMD_TMP_PREFIX}/dummy_https-${RSPAMD_PORT_DUMMY_HTTPS}.log
  ${result} =  Start Dummy Service  dummy_https.py  ${pid}  ${log}
  ...  ${RSPAMD_TESTDIR}/util/dummy_http.py
  ...  -c  ${RSPAMD_TESTDIR}/util/server.pem  -k  ${RSPAMD_TESTDIR}/util/server.pem
  ...  -pf  ${pid}  -p  ${RSPAMD_PORT_DUMMY_HTTPS}
  Wait Until Dummy Listening  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_DUMMY_HTTPS}
  Export Scoped Variables  ${RSPAMD_SCOPE}  DUMMY_HTTPS_PROC=${result}

Run Dummy Llm
  ${pid} =  Set Variable  ${RSPAMD_TMP_PREFIX}/dummy_llm-${RSPAMD_PORT_DUMMY_HTTP}.pid
  ${log} =  Set Variable  ${RSPAMD_TMP_PREFIX}/dummy_llm-${RSPAMD_PORT_DUMMY_HTTP}.log
  ${result} =  Start Dummy Service  dummy_llm.py  ${pid}  ${log}
  ...  ${RSPAMD_TESTDIR}/util/dummy_llm.py  ${RSPAMD_PORT_DUMMY_HTTP}  ${pid}
  Wait Until Dummy Listening  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_DUMMY_HTTP}
  Export Scoped Variables  ${RSPAMD_SCOPE}  DUMMY_LLM_PROC=${result}

Dummy Llm Teardown
  Terminate Process  ${DUMMY_LLM_PROC}
  Wait For Process  ${DUMMY_LLM_PROC}

Dummy Http Teardown
  Terminate Process  ${DUMMY_HTTP_PROC}
  Wait For Process  ${DUMMY_HTTP_PROC}

Dummy Https Teardown
  Terminate Process  ${DUMMY_HTTPS_PROC}
  Wait For Process  ${DUMMY_HTTPS_PROC}

Run Dummy Http Early Response
  ${pid} =  Set Variable  ${RSPAMD_TMP_PREFIX}/dummy_http_early-${RSPAMD_PORT_DUMMY_HTTP_EARLY}.pid
  ${log} =  Set Variable  ${RSPAMD_TMP_PREFIX}/dummy_http_early-${RSPAMD_PORT_DUMMY_HTTP_EARLY}.log
  ${result} =  Start Dummy Service  dummy_http_early_response.py  ${pid}  ${log}
  ...  ${RSPAMD_TESTDIR}/util/dummy_http_early_response.py  -pf  ${pid}  -p  ${RSPAMD_PORT_DUMMY_HTTP_EARLY}
  Wait Until Dummy Listening  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_DUMMY_HTTP_EARLY}
  Export Scoped Variables  ${RSPAMD_SCOPE}  DUMMY_HTTP_EARLY_PROC=${result}

Dummy Http Early Teardown
  Terminate Process  ${DUMMY_HTTP_EARLY_PROC}
  Wait For Process  ${DUMMY_HTTP_EARLY_PROC}

Start Dummy Smtp
  [Documentation]  Start dummy_smtp.py and block until it is listening,
  ...  then return the process handle for teardown. No connect probe here:
  ...  the smtp helper runs single-threaded and its modes hold the handler
  ...  (silent sleeps 30s; greeting modes drive a state machine and write a
  ...  status file), so a probe connection would borrow the very session
  ...  the scan needs -- the PID barrier in Start Dummy Service is correct.
  ...  @{extra} carries optional flags such as --status-file / --between-wait.
  [Arguments]  ${port}  ${mode}  ${host}  ${pidfile}  @{extra}
  ${log} =  Set Variable  ${RSPAMD_TMP_PREFIX}/dummy_smtp-${mode}-${host}.log
  ${result} =  Start Dummy Service  dummy_smtp.py  ${pidfile}  ${log}
  ...  ${RSPAMD_TESTDIR}/util/dummy_smtp.py  --port  ${port}  --mode  ${mode}
  ...  --host  ${host}  --pid-file  ${pidfile}  @{extra}
  RETURN  ${result}
