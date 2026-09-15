*** Settings ***
Suite Setup     Fuzzy Count Scan Setup
Suite Teardown  Rspamd Redis Teardown
Resource        lib.robot

*** Variables ***
# Counts digests independently of the scan match heuristics: in this dedicated
# database every hash except the scan progress is a fuzzy digest
${COUNT_HASHES_SCRIPT}  local n = 0 for _, k in ipairs(redis.call('KEYS', '*')) do if k ~= 'fuzzy_count_scan' and redis.call('TYPE', k).ok == 'hash' then n = n + 1 end end return n
${COUNT_SCAN_SETTINGS}  sync = 1s; count_scan { interval = 1s; initial_delay = 0; checkpoint_interval = 0.1s; batch = 10; duty_cycle = 1.0; }
@{COUNT_SCAN_MESSAGES}  ${RSPAMD_TESTDIR}/messages/spam_message.eml  ${RSPAMD_TESTDIR}/messages/zip.eml

*** Test Cases ***
Count Scan Replaces A Bogus Counter
  Redis Command  SET  fuzzy_count  100500
  Wait Until Keyword Succeeds  30x  0.5s  Published Fuzzy Count Should Be  0

Count Follows Additions
  FOR  ${message}  IN  @{COUNT_SCAN_MESSAGES}
    Fuzzy Add Test  ${message}
  END
  ${stored} =  Stored Fuzzy Hashes
  Should Be True  ${stored} > 0
  Wait Until Keyword Succeeds  30x  0.5s  Published Fuzzy Count Should Be  ${stored}
  Wait Until Keyword Succeeds  30x  0.5s  Fuzzy Storage Should Report  ${stored}
  Set Suite Variable  ${STORED_AFTER_ADD}  ${stored}

Relearning Does Not Inflate Count
  Fuzzy Add Test  ${COUNT_SCAN_MESSAGES}[0]
  Wait For Next Count Scan Pass
  ${stored} =  Stored Fuzzy Hashes
  Should Be Equal As Integers  ${stored}  ${STORED_AFTER_ADD}
  Published Fuzzy Count Should Be  ${STORED_AFTER_ADD}

Count Follows Deletions
  Fuzzy Delete Test  ${COUNT_SCAN_MESSAGES}[0]
  ${stored} =  Stored Fuzzy Hashes
  Should Be True  ${stored} < ${STORED_AFTER_ADD}
  Wait Until Keyword Succeeds  30x  0.5s  Published Fuzzy Count Should Be  ${stored}

*** Keywords ***
Fuzzy Count Scan Setup
  Set Suite Variable  ${RSPAMD_SETTINGS_FUZZY_WORKER}  ${COUNT_SCAN_SETTINGS}
  Fuzzy Setup Plain Siphash

Redis Command
  [Arguments]  @{args}
  ${result} =  Run Process  redis-cli  -h  ${RSPAMD_REDIS_ADDR}  -p  ${RSPAMD_REDIS_PORT}  @{args}
  Should Be Equal As Integers  ${result.rc}  0  msg=${result.stderr}
  RETURN  ${result.stdout}

Stored Fuzzy Hashes
  ${count} =  Redis Command  EVAL  ${COUNT_HASHES_SCRIPT}  0
  RETURN  ${count}

Published Fuzzy Count Should Be
  [Arguments]  ${expected}
  ${published} =  Redis Command  GET  fuzzy_count
  Should Be Equal As Integers  ${published}  ${expected}

Fuzzy Storage Should Report
  [Arguments]  ${expected}
  ${result} =  Run Process  ${RSPAMADM}  control  -s  ${RSPAMD_TMPDIR}/rspamd.sock  -c  fuzzystat
  Should Match Regexp  ${result.stdout}  "fuzzy_stored":${expected}\[,}]

Wait For Next Count Scan Pass
  ${before} =  Redis Command  HGET  fuzzy_count_scan  last_done
  Wait Until Keyword Succeeds  30x  0.5s  Count Scan Pass Should Complete After  ${before}

Count Scan Pass Should Complete After
  [Arguments]  ${before}
  ${last_done} =  Redis Command  HGET  fuzzy_count_scan  last_done
  Should Not Be Equal  ${last_done}  ${before}
