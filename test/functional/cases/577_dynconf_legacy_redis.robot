*** Settings ***
Documentation    Import of the Redis hash of the deprecated dynamic_conf module into dynconf (Redis backend):
...              scores and actions are stored once by the primary controller, the lists of symbols are not
...              imported (the old module never applied them), the hash is kept and only marked, so a reset of
...              the overrides is not undone by a restart.
Suite Setup      Legacy Redis Setup
Suite Teardown   Rspamd Redis Teardown
Library          Process
Library          OperatingSystem
Library          ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource         ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables        ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}               ${RSPAMD_TESTDIR}/configs/dynconf_legacy_redis.conf
${REDIS_SCOPE}          Suite
${RSPAMD_SCOPE}         Suite
${RSPAMD_URL_TLD}       ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${MESSAGE}              ${RSPAMD_TESTDIR}/messages/dynconf_hello.eml
${LEGACY_HASH}          legacy_hash
${LEGACY_DATA}          {"scores": {"DYN_HELLO": 40, "NO_SUCH_SYMBOL": 1}, "actions": {"reject": 200, "add_header": 25}, "symbols_disabled": ["DYN_WORLD", "NO_SUCH_SYMBOL"], "symbols_enabled": ["DYN_HELLO"]}

*** Test Cases ***
The deprecated module warns
  [Documentation]  the backend is Redis: only the deprecation warning, no error about data that is not applied
  Log Should Contain  is deprecated and replaced by the dynconf framework
  Log Should Not Contain  its redis data is NOT applied

Hash is imported and applies to every worker
  Scores Should Reach All Workers  40.0
  Wait Until Keyword Succeeds  20x  0.5s  Required Score Should Be Seen By All Workers  200
  Expect Action  add header
  ${dump} =  Dump Module  scores
  Should Be Equal As Numbers  ${dump}[modules][scores][overrides][redis][values][DYN_HELLO]  40.0
  Should Not Contain  ${dump}[modules][scores][overrides][redis][values]  NO_SUCH_SYMBOL
  ${dump} =  Dump Module  actions
  Should Be Equal As Numbers  ${dump}[modules][actions][overrides][redis][values][reject]  200
  Should Be Equal As Numbers  ${dump}[modules][actions][overrides][redis][values][add header]  25

The lists of symbols are not imported
  [Documentation]  symbols_disabled and symbols_enabled are logged once, with the reason, and nothing else
  Wait Until Keyword Succeeds  20x  0.5s  Symbol Should Be Present For All Workers  DYN_WORLD
  Module Should Have No Overrides  symbols
  Log Should Contain  symbols_disabled (2 entries) is not imported
  Log Should Contain  symbols_enabled (1 entries) is not imported
  Log Should Contain  the previous implementation never applied it at runtime

The hash is kept and marked as imported
  ${stored} =  Redis Command  HGET  ${LEGACY_HASH}  d
  Should Be Equal  ${stored}  ${LEGACY_DATA}
  ${marked} =  Redis Command  HEXISTS  ${LEGACY_HASH}  dynconf_imported
  Should Be Equal As Integers  ${marked}  1

The import is done once
  [Documentation]  A reset of the overrides is not undone by a restart
  FOR  ${module}  IN  scores  actions
    ${result} =  Controller Post  /plugins/dynconf/reset?module=${module}
    Should Be Equal As Integers  ${result}[0]  200
  END
  Restart Rspamd
  Scan Message
  Expect Symbol With Score  DYN_HELLO  2.0
  Expect Symbol  DYN_WORLD
  Expect Required Score  100
  Expect Action  no action
  Module Should Have No Overrides  scores
  Module Should Have No Overrides  actions

*** Keywords ***
Legacy Redis Setup
  [Documentation]  The hash of the old module has to exist before rspamd starts
  Run Redis
  Redis HSET  ${LEGACY_HASH}  v  3
  Redis HSET  ${LEGACY_HASH}  d  ${LEGACY_DATA}
  Rspamd Setup

Redis Command
  [Arguments]  @{args}
  ${result} =  Run Process  redis-cli  -h  ${RSPAMD_REDIS_ADDR}  -p  ${RSPAMD_REDIS_PORT}  @{args}
  Should Be Equal As Integers  ${result.rc}  0
  RETURN  ${result.stdout}

Log Should Contain
  [Arguments]  ${text}
  ${log} =  Get File  ${RSPAMD_TMPDIR}/rspamd.log
  Should Contain  ${log}  ${text}

Log Should Not Contain
  [Arguments]  ${text}
  ${log} =  Get File  ${RSPAMD_TMPDIR}/rspamd.log
  Should Not Contain  ${log}  ${text}

Scan Message
  Scan File  ${MESSAGE}

Controller Post
  [Arguments]  ${path}  ${body}=${EMPTY}
  ${result} =  HTTP  POST  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  ${path}  ${body}
  ${text} =  Evaluate  $result[1].decode('utf-8')
  RETURN  ${result}[0]  ${text}

Dump Module
  [Arguments]  ${module}
  ${result} =  HTTP  GET  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /plugins/dynconf/dump?module=${module}
  Should Be Equal As Integers  ${result}[0]  200
  ${json} =  Check JSON  ${result}[1]
  RETURN  ${json}[data]

Module Should Have No Overrides
  [Arguments]  ${module}
  ${dump} =  Dump Module  ${module}
  Should Be Empty  ${dump}[modules][${module}][overrides]

Scan Several Times
  [Documentation]  The scanning workers are separate processes: one scan can hit any of them
  [Arguments]  ${keyword}  @{args}
  FOR  ${i}  IN RANGE  12
    Run Keyword  ${keyword}  @{args}
  END

Score Of DYN_HELLO Should Be
  [Arguments]  ${expected}
  Scan Message
  Expect Symbol With Score  DYN_HELLO  ${expected}

Scores Should Reach All Workers
  [Arguments]  ${expected}
  Wait Until Keyword Succeeds  20x  0.5s  Scan Several Times  Score Of DYN_HELLO Should Be  ${expected}

Required Score Should Be
  [Arguments]  ${expected}
  Scan Message
  Expect Required Score  ${expected}

Required Score Should Be Seen By All Workers
  [Arguments]  ${expected}
  Scan Several Times  Required Score Should Be  ${expected}

Symbol Should Be Present
  [Arguments]  ${symbol}
  Scan Message
  Expect Symbol  ${symbol}

Symbol Should Be Present For All Workers
  [Arguments]  ${symbol}
  Scan Several Times  Symbol Should Be Present  ${symbol}

Restart Rspamd
  Terminate Process  ${RSPAMD_PROCESS}
  Wait For Process  ${RSPAMD_PROCESS}
  Wait For Rspamd Ports Released
  Run Rspamd
