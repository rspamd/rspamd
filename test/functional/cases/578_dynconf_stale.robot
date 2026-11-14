*** Settings ***
Documentation    Dynamic configuration (the file backend): override.d beats a dynamic action threshold; names
...              that do not exist any more (stale) in the stored overrides are skipped and reported when a backend
...              delivers them, but a write of the controller still refuses them; the deprecated dynamic_conf
...              module reports that its Redis data is not applied.
Suite Setup      Rspamd Setup
Suite Teardown   Rspamd Teardown
Library          Process
Library          OperatingSystem
Library          ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource         ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables        ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}               ${RSPAMD_TESTDIR}/configs/dynconf_stale.conf
${RSPAMD_SCOPE}         Suite
${RSPAMD_URL_TLD}       ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${MESSAGE}              ${RSPAMD_TESTDIR}/messages/dynconf_hello.eml

*** Test Cases ***
The deprecated module says that its redis data is not applied
  [Documentation]  the dynconf backend is `file`: nothing switches it to Redis by itself
  Log Should Contain  the dynamic_conf module is deprecated and replaced by the dynconf framework, and its redis data is NOT applied
  ${log} =  Get File  ${RSPAMD_TMPDIR}/rspamd.log
  Should Match Regexp  ${log}  \\[error\\][^\\n]*its redis data is NOT applied
  Log Should Contain  Set `dynconf { backend = "redis"; }` to apply it

Baseline thresholds
  [Documentation]  override.d defines greylist, the main file does not
  Action Threshold Should Be  reject  100
  Action Threshold Should Be  add header  30
  Action Threshold Should Be  greylist  20

Override.d beats a dynamic threshold
  ${result} =  Controller Post  /saveactions  [200, null, 60, 5]
  Should Be Equal As Integers  ${result}[0]  500
  Should Contain  ${result}[1]  greylist
  Should Contain  ${result}[1]  priority 10
  Should Contain  ${result}[1]  cannot be changed dynamically
  Module Should Have No Overrides  actions
  Action Threshold Should Be  reject  100
  Action Threshold Should Be  greylist  20
  ${result} =  Controller Post  /plugins/dynconf/set?module=actions  {"greylist": 5}
  Should Be Equal As Integers  ${result}[0]  400
  Should Contain  ${result}[1]  priority 10
  Module Should Have No Overrides  actions

A dynamic threshold beats the main file
  [Documentation]  the request that leaves the greylist field alone is fine
  ${result} =  Controller Post  /saveactions  [200, null, 60, null]
  Should Be Equal As Integers  ${result}[0]  200
  Wait Until Keyword Succeeds  20x  0.5s  Required Score Should Be Seen By All Workers  200
  Action Threshold Should Be  reject  200
  Action Threshold Should Be  add header  60
  Action Threshold Should Be  greylist  20
  ${result} =  Controller Post  /plugins/dynconf/reset?module=actions
  Should Be Equal As Integers  ${result}[0]  200
  Wait Until Keyword Succeeds  20x  0.5s  Required Score Should Be Seen By All Workers  100
  Action Threshold Should Be  add header  30

A masked threshold that a backend delivers is skipped and reported
  [Documentation]  the stored override names greylist (override.d wins) and reject (it applies)
  Write Overrides  {"v": 1, "modules": {"actions": {"v": 1, "o": {"greylist": 5, "reject": 150}}}}
  Wait Until Keyword Succeeds  20x  0.5s  Required Score Should Be Seen By All Workers  150
  Action Threshold Should Be  greylist  20
  Action Threshold Should Be  reject  150
  ${dump} =  Dump All
  Should Contain  ${dump}[modules][actions][skipped][0]  greylist
  Should Contain  ${dump}[modules][actions][skipped][0]  priority 10
  Should Contain  ${dump}[backends][file][last_error]  greylist
  Log Should Contain  skip greylist
  # A check that delivers nothing does not clear the report: it stays for as long as the entry is skipped
  Sleep  3s
  ${dump} =  Dump All
  Should Contain  ${dump}[backends][file][last_error]  greylist
  Should Contain  ${dump}[modules][actions][skipped][0]  greylist
  Reset Overrides  actions
  Wait Until Keyword Succeeds  20x  0.5s  Required Score Should Be Seen By All Workers  100

A write that names the masked stored entry again is refused, not reported as a success
  [Documentation]  the stored override holds greylist = 5 already (skipped, override.d wins): the same value
  ...              changes nothing, but the write is checked all the same
  Write Overrides  {"v": 10, "modules": {"actions": {"v": 10, "o": {"greylist": 5, "reject": 150}}}}
  Wait Until Keyword Succeeds  20x  0.5s  Required Score Should Be Seen By All Workers  150
  ${result} =  Controller Post  /saveactions  [null, null, null, 5]
  Should Be Equal As Integers  ${result}[0]  500
  Should Contain  ${result}[1]  greylist
  Should Contain  ${result}[1]  priority 10
  Action Threshold Should Be  greylist  20
  Reset Overrides  actions
  Wait Until Keyword Succeeds  20x  0.5s  Required Score Should Be Seen By All Workers  100

A stale name in the stored scores is skipped, the rest is applied
  Write Overrides  {"v": 2, "modules": {"scores": {"v": 1, "o": {"DYN_HELLO": 40, "STALE_SYMBOL": 5}}}}
  Scores Should Reach All Workers  40.0
  ${dump} =  Dump All
  Should Be Equal  ${dump}[modules][scores][skipped][0]  unknown symbol STALE_SYMBOL
  Should Contain  ${dump}[backends][file][last_error]  unknown symbol STALE_SYMBOL
  Should Be Equal As Numbers  ${dump}[modules][scores][overrides][file][values][STALE_SYMBOL]  5
  Log Should Contain  skip STALE_SYMBOL: unknown symbol STALE_SYMBOL

A stale stored name does not block a write that does not touch it
  ${result} =  Controller Post  /savesymbols  [{"name": "DYN_WORLD", "value": 7.0}]
  Should Be Equal As Integers  ${result}[0]  200
  Should Be Equal  ${result}[1]  {"success":true}
  ${dump} =  Dump Module  scores
  Should Be Equal As Numbers  ${dump}[modules][scores][overrides][file][values][DYN_WORLD]  7.0
  Should Be Equal As Numbers  ${dump}[modules][scores][overrides][file][values][DYN_HELLO]  40.0
  Dictionary Should Contain Key  ${dump}[modules][scores][overrides][file][values]  STALE_SYMBOL

A write still refuses an unknown name
  ${result} =  Controller Post  /savesymbols  [{"name": "STALE_SYMBOL", "value": 3.0}]
  Should Be Equal As Integers  ${result}[0]  506
  Should Contain  ${result}[1]  unknown symbol STALE_SYMBOL
  ${result} =  Controller Post  /savesymbols  [{"name": "DYN_HELLO", "value": 41.0}, {"name": "NO_SUCH_SYMBOL", "value": 3.0}]
  Should Be Equal As Integers  ${result}[0]  506
  Should Contain  ${result}[1]  unknown symbol NO_SUCH_SYMBOL
  ${result} =  Controller Post  /plugins/dynconf/set?module=scores  {"NO_SUCH_SYMBOL": 3}
  Should Be Equal As Integers  ${result}[0]  400
  Should Contain  ${result}[1]  unknown symbol NO_SUCH_SYMBOL
  ${dump} =  Dump Module  scores
  Should Be Equal As Numbers  ${dump}[modules][scores][overrides][file][values][DYN_HELLO]  40.0
  Should Not Contain  ${dump}[modules][scores][overrides][file][values]  NO_SUCH_SYMBOL

The stale name does not hold up a restart
  Restart Rspamd
  Scan Message
  Expect Symbol With Score  DYN_HELLO  40.0
  Expect Symbol With Score  DYN_WORLD  7.0

A null removes the stale entry
  ${result} =  Controller Post  /savesymbols  [{"name": "STALE_SYMBOL", "value": null}]
  Should Be Equal As Integers  ${result}[0]  200
  ${dump} =  Dump Module  scores
  Should Not Contain  ${dump}[modules][scores][overrides][file][values]  STALE_SYMBOL
  Should Be Equal As Numbers  ${dump}[modules][scores][overrides][file][values][DYN_HELLO]  40.0
  Should Not Contain  ${dump}[modules][scores]  skipped
  Reset Overrides  scores
  Scores Should Reach All Workers  2.0

*** Keywords ***
Log Should Contain
  [Arguments]  ${text}
  ${log} =  Get File  ${RSPAMD_TMPDIR}/rspamd.log
  Should Contain  ${log}  ${text}

Scan Message
  Scan File  ${MESSAGE}

Write Overrides
  [Documentation]  what another node (or an operator) stores in the file; the workers poll it
  [Arguments]  ${text}
  Create File  ${RSPAMD_TMPDIR}/rspamd_dynconf.json  ${text}

Reset Overrides
  [Arguments]  ${module}
  ${result} =  Controller Post  /plugins/dynconf/reset?module=${module}
  Should Be Equal As Integers  ${result}[0]  200

Controller Post
  [Arguments]  ${path}  ${body}=${EMPTY}
  ${result} =  HTTP  POST  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  ${path}  ${body}
  ${text} =  Evaluate  $result[1].decode('utf-8')
  RETURN  ${result}[0]  ${text}

Dump All
  ${result} =  HTTP  GET  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /plugins/dynconf/dump
  Should Be Equal As Integers  ${result}[0]  200
  ${json} =  Check JSON  ${result}[1]
  RETURN  ${json}[data]

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

Action Threshold Should Be
  [Documentation]  what the controller has (the workers follow it, see Required Score Should Be Seen By All Workers)
  [Arguments]  ${action}  ${expected}
  ${result} =  HTTP  GET  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /actions
  Should Be Equal As Integers  ${result}[0]  200
  ${json} =  Check JSON  ${result}[1]
  ${found} =  Evaluate  [a['value'] for a in $json if a['action'] == $action]
  Should Not Be Empty  ${found}  msg=no action ${action}
  Should Be Equal As Numbers  ${found}[0]  ${expected}

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

Restart Rspamd
  Terminate Process  ${RSPAMD_PROCESS}
  Wait For Process  ${RSPAMD_PROCESS}
  Wait For Rspamd Ports Released
  Run Rspamd
