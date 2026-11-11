*** Settings ***
Test Teardown   Rspamd Redis Teardown
Test Template   Unix Count Scan Works
Resource        lib.robot

*** Variables ***
${REDIS_SCOPE}   Test
${RSPAMD_SCOPE}  Test
${MESSAGE}      ${RSPAMD_TESTDIR}/messages/spam_message.eml

*** Test Cases ***
Count Scan Over Unix Socket             0
Count Scan With Stats Over Unix Socket  1

*** Keywords ***
Unix Count Scan Works
  [Arguments]  ${sample}
  ${redis_dir} =  Make Temporary Directory
  Set Test Variable  ${REDIS_TMPDIR}  ${redis_dir}
  Set Test Variable  ${REDIS_SOCKET}  ${redis_dir}/redis.sock
  ${redis} =  Start Process  redis-server  --port  0  --unixsocket  ${REDIS_SOCKET}
  ...  --unixsocketperm  777  --save  ${EMPTY}  --dir  ${redis_dir}
  ...  stdout=${redis_dir}/redis.log  stderr=STDOUT
  Set Test Variable  ${REDIS_PROCESS}  ${redis}
  Wait Until Keyword Succeeds  5s  0.1s  Unix Redis Should Be Ready

  Set Test Variable  ${RSPAMD_FUZZY_ALGORITHM}  siphash
  Set Test Variable  ${RSPAMD_SETTINGS_FUZZY_WORKER}
  ...  servers = "${REDIS_SOCKET}"; sync = 1s; count_scan { interval = 1s; initial_delay = 0; batch = 10; duty_cycle = 1; stats_sample = ${sample}; }
  Unix Redis Command  SET  fuzzy_count  100500
  Rspamd Setup
  Wait Until Keyword Succeeds  15s  0.5s  Unix Fuzzy Count Should Be  0

  Fuzzy Add Test  ${MESSAGE}
  ${stored} =  Unix Redis Command  EVAL  local n = 0 for _, k in ipairs(redis.call('KEYS', '*')) do if k ~= 'fuzzy_count_scan' and redis.call('TYPE', k).ok == 'hash' then n = n + 1 end end return n  0
  Should Be True  ${stored} > 0
  Wait Until Keyword Succeeds  15s  0.5s  Unix Fuzzy Count Should Be  ${stored}
  IF  ${sample} == 1
    ${raw} =  Unix Redis Command  GET  fuzzy_stats
    ${stats} =  Evaluate  json.loads($raw)  modules=json
    Should Be Equal As Integers  ${stats}[sampled]  ${stored}
    Should Be Equal  ${stats}[server]  unix:${REDIS_SOCKET}
  END
  ${errors} =  Grep File  ${RSPAMD_TMPDIR}/rspamd.log  cannot send SCAN request
  Should Be Empty  ${errors}

Unix Redis Command
  [Arguments]  @{args}
  ${result} =  Run Process  redis-cli  -s  ${REDIS_SOCKET}  @{args}
  Should Be Equal As Integers  ${result.rc}  0  msg=${result.stderr}
  RETURN  ${result.stdout}

Unix Redis Should Be Ready
  ${reply} =  Unix Redis Command  PING
  Should Be Equal  ${reply}  PONG

Unix Fuzzy Count Should Be
  [Arguments]  ${expected}
  ${count} =  Unix Redis Command  GET  fuzzy_count
  Should Be Equal As Integers  ${count}  ${expected}
