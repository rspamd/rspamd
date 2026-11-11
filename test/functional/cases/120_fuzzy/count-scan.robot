*** Settings ***
Suite Setup     Fuzzy Count Scan Setup
Suite Teardown  Rspamd Redis Teardown
Resource        lib.robot

*** Variables ***
# Counts digests independently of the scan match heuristics: in this dedicated
# database every hash except the scan progress is a fuzzy digest
${COUNT_HASHES_SCRIPT}  local n = 0 for _, k in ipairs(redis.call('KEYS', '*')) do if k ~= 'fuzzy_count_scan' and redis.call('TYPE', k).ok == 'hash' then n = n + 1 end end return n
# Sum and maximum of the primary slot weights, to compare with the sampled statistics
${WEIGHTS_SCRIPT}  local s, m = 0, 0 for _, k in ipairs(redis.call('KEYS', '*')) do if k ~= 'fuzzy_count_scan' and redis.call('TYPE', k).ok == 'hash' then local v = tonumber(redis.call('HGET', k, 'V')) or 0 s = s + v if v > m then m = v end end end return {s, m}
# stats_sample = 1 reads every digest, so the published statistics are exact
${COUNT_SCAN_SETTINGS}  sync = 1s; count_scan { interval = 1s; initial_delay = 0; checkpoint_interval = 0.1s; batch = 10; duty_cycle = 1.0; stats_sample = 1; }
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

Storage Statistics Follow The Count
  Wait Until Keyword Succeeds  30x  0.5s  Published Storage Stats Should Cover  ${STORED_AFTER_ADD}
  ${stats} =  Published Storage Stats
  Should Be Equal As Integers  ${stats}[sample]  1
  Should Be Equal As Integers  ${stats}[sampled]  ${STORED_AFTER_ADD}
  # Everything so far was learned with flag 1 only
  ${weights} =  Redis Command  EVAL  ${WEIGHTS_SCRIPT}  0
  ${sum}  ${max} =  Evaluate  [int(x) for x in re.findall(r'\\d+', $weights)]  modules=re
  Should Be Equal As Integers  ${stats}[flags][${RSPAMD_FLAG1_NUMBER}][count]  ${STORED_AFTER_ADD}
  ${avg} =  Evaluate  $sum / int($STORED_AFTER_ADD)
  Should Be Equal As Numbers  ${stats}[flags][${RSPAMD_FLAG1_NUMBER}][avg_weight]  ${avg}
  Should Be Equal As Integers  ${stats}[flags][${RSPAMD_FLAG1_NUMBER}][max_weight]  ${max}
  Should Be Equal As Integers  ${stats}[multi_flag]  0
  Should Be True  ${stats}[shingled] > 0
  Should Be True  ${stats}[shingle_slots] >= ${stats}[shingled]
  Should Be Equal As Integers  ${stats}[age][1d]  ${STORED_AFTER_ADD}
  Should Be Equal As Integers  ${stats}[age][older]  0
  Wait Until Keyword Succeeds  30x  0.5s  Fuzzy Storage Should Report Storage Stats  ${STORED_AFTER_ADD}

Storage Statistics See Extra Flags
  Fuzzy Multi Flag Test  ${COUNT_SCAN_MESSAGES}[0]
  Wait For Next Count Scan Pass
  ${stats} =  Published Storage Stats
  Should Be Equal As Integers  ${stats}[sampled]  ${STORED_AFTER_ADD}
  Should Be Equal As Integers  ${stats}[flags][${RSPAMD_FLAG1_NUMBER}][count]  ${STORED_AFTER_ADD}
  Should Be Equal As Integers  ${stats}[flags][${RSPAMD_FLAG2_NUMBER}][count]  1
  Should Be Equal As Integers  ${stats}[multi_flag]  1

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

Published Storage Stats
  ${raw} =  Redis Command  GET  fuzzy_stats
  ${stats} =  Evaluate  json.loads($raw)  modules=json
  RETURN  ${stats}

Published Storage Stats Should Cover
  [Arguments]  ${expected}
  ${stats} =  Published Storage Stats
  Should Be Equal As Integers  ${stats}[found]  ${expected}

Fuzzy Storage Should Report Storage Stats
  [Arguments]  ${expected}
  ${result} =  Run Process  ${RSPAMADM}  control  -s  ${RSPAMD_TMPDIR}/rspamd.sock  -c  fuzzystat
  Should Match Regexp  ${result.stdout}  "storage":\{
  Should Match Regexp  ${result.stdout}  "found":${expected}\[,}]

Wait For Next Count Scan Pass
  ${before} =  Redis Command  HGET  fuzzy_count_scan  last_done
  Wait Until Keyword Succeeds  30x  0.5s  Count Scan Pass Should Complete After  ${before}

Count Scan Pass Should Complete After
  [Arguments]  ${before}
  ${last_done} =  Redis Command  HGET  fuzzy_count_scan  last_done
  Should Not Be Equal  ${last_done}  ${before}
