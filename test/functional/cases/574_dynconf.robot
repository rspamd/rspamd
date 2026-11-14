*** Settings ***
Documentation    Dynamic configuration framework (lua_dynconf) with the Redis backend:
...              overrides written to Redis or through the controller change the behaviour of
...              a C module (chartable) and of a Lua module (aliases) and are rolled back
...              when removed; paths that are not declared dynamic are rejected.
Suite Setup      Rspamd Redis Setup
Suite Teardown   Rspamd Redis Teardown
Library          Process
Library          ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource         ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables        ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}               ${RSPAMD_TESTDIR}/configs/dynconf.conf
${REDIS_SCOPE}          Suite
${RSPAMD_SCOPE}         Suite
${RSPAMD_URL_TLD}       ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${DYNCONF_KEY}          rspamd_dynconf_test
${CHARTABLE_MESSAGE}    ${RSPAMD_TESTDIR}/messages/chartable_english_diacritics.eml
${ALIASES_MESSAGE}      ${RSPAMD_TESTDIR}/messages/aliases_plus.eml
${SETTINGS_CHARTABLE}   {symbols_enabled = [R_MIXED_CHARSET]}
${SETTINGS_ALIASES}     {symbols_enabled = [ALIASES_CHECK, TAGGED_RCPT]}

*** Test Cases ***
Baseline without overrides
  Mixed Charset Should Be Reported
  Tagged Recipient Should Be Reported

Dump lists dynamic paths and no overrides
  ${dump} =  Dump Module  chartable
  Should Be True  ${dump}[enabled]
  Should Contain  ${dump}[modules][chartable][dynamic]  threshold
  Should Contain  ${dump}[modules][chartable][dynamic]  max_word_len
  Should Be Empty  ${dump}[modules][chartable][overrides]
  ${dump} =  Dump Module  aliases
  Should Contain  ${dump}[modules][aliases][dynamic]  enable_plus_aliases
  Should Be Empty  ${dump}[modules][aliases][overrides]

Redis override of a C module option takes effect and is removed
  [Documentation]  chartable.threshold is applied through the C subscriber; a huge threshold
  ...              silences R_MIXED_CHARSET and the removal of the override restores it
  Redis Write Override  chartable  1  {"threshold": 1000}
  Wait Until Keyword Succeeds  20x  0.5s  Mixed Charset Should Not Be Reported
  # The controller worker runs its own check, it may lag behind the scanning one
  Wait Until Keyword Succeeds  20x  0.5s  Effective Threshold Should Be  1000
  Redis Remove Override  chartable  2
  Wait Until Keyword Succeeds  20x  0.5s  Mixed Charset Should Be Reported
  Wait Until Keyword Succeeds  20x  0.5s  Module Should Have No Overrides  chartable

Redis override that touches a non-dynamic path is ignored
  Redis Write Override  aliases  3  {"symbol_tagged_rcpt": "NOT_DYNAMIC"}
  # Give the periodic check time to see the new version and reject the update
  Sleep  3s
  Tagged Recipient Should Be Reported
  Redis Remove Override  aliases  4
  Tagged Recipient Should Be Reported

Controller override of a Lua module option takes effect and is reset
  [Documentation]  Written through /plugins/dynconf/set: stored in Redis, applied by the
  ...              controller at once and picked up by the scanning worker through its check
  ${result} =  Controller Set  aliases  {"enable_plus_aliases": false, "enable_gmail_rules": false}
  Should Be Equal As Integers  ${result}[0]  200
  Wait Until Keyword Succeeds  20x  0.5s  Tagged Recipient Should Not Be Reported
  ${dump} =  Dump Module  aliases
  Should Not Be True  ${dump}[modules][aliases][effective][enable_plus_aliases]
  Should Not Be Empty  ${dump}[modules][aliases][overrides]
  ${result} =  Controller Post  /plugins/dynconf/reset?module=aliases
  Should Be Equal As Integers  ${result}[0]  200
  Wait Until Keyword Succeeds  20x  0.5s  Tagged Recipient Should Be Reported
  ${dump} =  Dump Module  aliases
  Should Be True  ${dump}[modules][aliases][effective][enable_plus_aliases]
  Should Be Empty  ${dump}[modules][aliases][overrides]

Controller override of a C module option takes effect and is reset
  ${result} =  Controller Set  chartable  {"threshold": 1000}
  Should Be Equal As Integers  ${result}[0]  200
  Wait Until Keyword Succeeds  20x  0.5s  Mixed Charset Should Not Be Reported
  ${result} =  Controller Post  /plugins/dynconf/reset?module=chartable
  Should Be Equal As Integers  ${result}[0]  200
  Wait Until Keyword Succeeds  20x  0.5s  Mixed Charset Should Be Reported

Controller override of a per-flag limit of a C module takes effect and is reset
  [Documentation]  rule.*.fuzzy_map.*.hits_limit is looked up by the name of the fuzzy_map entry
  ${result} =  Controller Set  fuzzy_check  {"rule": {"dyn": {"fuzzy_map": {"FUZZY_DYN_FLAG": {"hits_limit": 7}}}}}
  Should Be Equal As Integers  ${result}[0]  200
  Wait Until Keyword Succeeds  20x  0.5s  Rspamd Log Should Contain  flag 11 (FUZZY_DYN_FLAG) hits limit changed from 5.00 to 7.00
  ${result} =  Controller Post  /plugins/dynconf/reset?module=fuzzy_check
  Should Be Equal As Integers  ${result}[0]  200
  Wait Until Keyword Succeeds  20x  0.5s  Rspamd Log Should Contain  flag 11 (FUZZY_DYN_FLAG) hits limit changed from 7.00 to 5.00

Controller serves the schema of a module that publishes one
  [Documentation]  the schema is found by the plugins.<name> convention
  ${result} =  HTTP  GET  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /plugins/dynconf/schema?module=history_redis
  Should Be Equal As Integers  ${result}[0]  200
  ${json} =  Check JSON  ${result}[1]
  Should Contain  ${json}[data][dynamic]  nrows
  Should Not Be Empty  ${json}[data][schema]
  ${result} =  HTTP  GET  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /plugins/dynconf/schema?module=aliases
  Should Be Equal As Integers  ${result}[0]  404

Controller rejects a path that is not dynamic
  ${result} =  Controller Set  aliases  {"symbol_tagged_rcpt": "NOT_DYNAMIC"}
  Should Be Equal As Integers  ${result}[0]  400
  Should Contain  ${result}[1]  not dynamic
  ${result} =  Controller Set  aliases  {"enable_plus_aliases": false, "max_recursion_depth": 5, "rspamd_aliases": {"a@example.com": "b@example.com"}}
  Should Be Equal As Integers  ${result}[0]  400
  ${dump} =  Dump Module  aliases
  Should Be Empty  ${dump}[modules][aliases][overrides]
  Tagged Recipient Should Be Reported

Controller rejects a value of a wrong type
  ${result} =  Controller Set  aliases  {"enable_plus_aliases": "no"}
  Should Be Equal As Integers  ${result}[0]  400
  Tagged Recipient Should Be Reported

Controller rejects a value refused by a C module
  ${result} =  Controller Set  chartable  {"threshold": "high"}
  Should Be Equal As Integers  ${result}[0]  400
  Mixed Charset Should Be Reported
  Module Should Have No Overrides  chartable

Controller rejects an unknown module
  ${result} =  Controller Set  no_such_module  {"enable": true}
  Should Be Equal As Integers  ${result}[0]  404

Controller rejects an invalid body
  ${result} =  Controller Set  aliases  [1, 2, 3]
  Should Be Equal As Integers  ${result}[0]  400
  ${result} =  Controller Set  aliases  not json at all
  Should Be Equal As Integers  ${result}[0]  400

*** Keywords ***
Mixed Charset Should Be Reported
  Scan File  ${CHARTABLE_MESSAGE}  Settings=${SETTINGS_CHARTABLE}
  Expect Symbol  R_MIXED_CHARSET

Mixed Charset Should Not Be Reported
  Scan File  ${CHARTABLE_MESSAGE}  Settings=${SETTINGS_CHARTABLE}
  Do Not Expect Symbol  R_MIXED_CHARSET

Tagged Recipient Should Be Reported
  Scan File  ${ALIASES_MESSAGE}  Settings=${SETTINGS_ALIASES}
  ...  From=sender@external.com  Rcpt=user+tag@example.com
  Expect Symbol  TAGGED_RCPT

Tagged Recipient Should Not Be Reported
  Scan File  ${ALIASES_MESSAGE}  Settings=${SETTINGS_ALIASES}
  ...  From=sender@external.com  Rcpt=user+tag@example.com
  Do Not Expect Symbol  TAGGED_RCPT

Redis Write Override
  [Documentation]  The documented layout: field `m:<module>` holds {"v": N, "o": {...}} and the
  ...              global version field `v` is bumped to a new value
  [Arguments]  ${module}  ${version}  ${overrides}
  Redis HSET  ${DYNCONF_KEY}  m:${module}  {"v": ${version}, "o": ${overrides}}
  Redis HSET  ${DYNCONF_KEY}  v  ${version}

Redis Remove Override
  [Arguments]  ${module}  ${version}
  ${result} =  Run Process  redis-cli  -h  ${RSPAMD_REDIS_ADDR}  -p  ${RSPAMD_REDIS_PORT}
  ...  HDEL  ${DYNCONF_KEY}  m:${module}
  Should Be Equal As Integers  ${result.rc}  0
  Redis HSET  ${DYNCONF_KEY}  v  ${version}

Controller Set
  [Arguments]  ${module}  ${body}
  ${result} =  Controller Post  /plugins/dynconf/set?module=${module}  ${body}
  RETURN  ${result}

Controller Post
  [Arguments]  ${path}  ${body}=${EMPTY}
  ${result} =  HTTP  POST  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  ${path}  ${body}
  ${text} =  Evaluate  $result[1].decode('utf-8')
  RETURN  ${result}[0]  ${text}

Effective Threshold Should Be
  [Arguments]  ${expected}
  ${dump} =  Dump Module  chartable
  Should Be Equal As Numbers  ${dump}[modules][chartable][effective][threshold]  ${expected}

Rspamd Log Should Contain
  [Arguments]  ${text}
  ${log} =  Get File  ${RSPAMD_TMPDIR}/rspamd.log
  Should Contain  ${log}  ${text}

Module Should Have No Overrides
  [Arguments]  ${module}
  ${dump} =  Dump Module  ${module}
  Should Be Empty  ${dump}[modules][${module}][overrides]

Dump Module
  [Arguments]  ${module}
  ${result} =  HTTP  GET  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /plugins/dynconf/dump?module=${module}
  Should Be Equal As Integers  ${result}[0]  200
  ${json} =  Check JSON  ${result}[1]
  RETURN  ${json}[data]
