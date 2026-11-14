*** Settings ***
Documentation    Dynamic configuration with the defaults (the file backend): the legacy WebUI endpoints
...              /saveactions and /savesymbols store thresholds and scores, the changes reach every scanning
...              worker, survive a restart and are reset; a symbol can be switched off at runtime.
Suite Setup      Rspamd Setup
Suite Teardown   Rspamd Teardown
Library          Process
Library          OperatingSystem
Library          ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource         ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables        ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}               ${RSPAMD_TESTDIR}/configs/dynconf_file.conf
${RSPAMD_SCOPE}         Suite
${RSPAMD_URL_TLD}       ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${MESSAGE}              ${RSPAMD_TESTDIR}/messages/dynconf_hello.eml
${MESSAGE_COMPOSITE}    ${RSPAMD_TESTDIR}/messages/dynconf_composite.eml

*** Test Cases ***
Baseline without overrides
  Scan Message
  Expect Symbol With Score  DYN_HELLO  2.0
  Expect Symbol With Score  DYN_WORLD  3.0
  Expect Action  no action
  Expect Required Score  100
  ${dump} =  Dump Module  scores
  Should Be True  ${dump}[enabled]
  Should Be Empty  ${dump}[modules][scores][overrides]
  File Should Not Exist  ${RSPAMD_TMPDIR}/rspamd_dynconf.json

Savesymbols changes the score for every scanning worker
  ${result} =  Controller Post  /savesymbols  [{"name": "DYN_HELLO", "value": 40.0}]
  Should Be Equal As Integers  ${result}[0]  200
  Should Be Equal  ${result}[1]  {"success":true}
  Scores Should Reach All Workers  40.0
  Expect Action  add header
  ${dump} =  Dump Module  scores
  Should Be Equal As Numbers  ${dump}[modules][scores][overrides][file][values][DYN_HELLO]  40.0
  File Should Exist  ${RSPAMD_TMPDIR}/rspamd_dynconf.json

Savesymbols refuses an unknown symbol as a whole
  [Documentation]  a write is strict: nothing of the request is stored, the reply says what is wrong
  ${result} =  Controller Post  /savesymbols  [{"name": "DYN_WORLD", "value": 9.0}, {"name": "NO_SUCH_SYMBOL", "value": 5}]
  Should Be Equal As Integers  ${result}[0]  506
  Should Contain  ${result}[1]  unknown symbol NO_SUCH_SYMBOL
  ${dump} =  Dump Module  scores
  Should Not Contain  ${dump}[modules][scores][overrides][file][values]  NO_SUCH_SYMBOL
  Should Not Contain  ${dump}[modules][scores][overrides][file][values]  DYN_WORLD
  Should Be Equal As Numbers  ${dump}[modules][scores][overrides][file][values][DYN_HELLO]  40.0

Saveactions changes the thresholds for every scanning worker
  [Documentation]  the order is [reject, rewrite subject, add header, greylist]; null is an action that
  ...              is not configured
  ${result} =  Controller Post  /saveactions  [200, null, 60, null]
  Should Be Equal As Integers  ${result}[0]  200
  Should Be Equal  ${result}[1]  {"success":true}
  Wait Until Keyword Succeeds  20x  0.5s  Required Score Should Be Seen By All Workers  200
  Expect Action  no action
  ${dump} =  Dump Module  actions
  Should Be Equal As Numbers  ${dump}[modules][actions][overrides][file][values][reject]  200
  Should Be Equal As Numbers  ${dump}[modules][actions][overrides][file][values][add header]  60

Overrides survive a restart and apply to the very first scan
  Restart Rspamd
  Scan Message
  Expect Symbol With Score  DYN_HELLO  40.0
  Expect Required Score  200
  Expect Action  no action
  Controller Should Show  scores  DYN_HELLO

Legacy symbol and action values that equal the static ones remove the overrides
  ${result} =  Controller Post  /savesymbols  [{"name": "DYN_HELLO", "value": 2.0}]
  Should Be Equal As Integers  ${result}[0]  200
  ${result} =  Controller Post  /saveactions  [100, null, 30, null]
  Should Be Equal As Integers  ${result}[0]  200
  Scores Should Reach All Workers  2.0
  Wait Until Keyword Succeeds  20x  0.5s  Required Score Should Be Seen By All Workers  100
  Expect Action  no action
  Module Should Have No Overrides  scores
  Module Should Have No Overrides  actions

Nothing to save is reported
  ${result} =  Controller Post  /savesymbols  [{"name": "DYN_HELLO", "value": 2.0}]
  Should Be Equal As Integers  ${result}[0]  404
  ${result} =  Controller Post  /savesymbols  [{"name": "NO_SUCH_SYMBOL", "value": null}]
  Should Be Equal As Integers  ${result}[0]  404

Invalid requests are refused
  ${result} =  Controller Post  /savesymbols  not json
  Should Be Equal As Integers  ${result}[0]  400
  ${result} =  Controller Post  /saveactions  [1, 2, 3]
  Should Be Equal As Integers  ${result}[0]  400
  ${result} =  Controller Post  /saveactions  {"reject": 1}
  Should Be Equal As Integers  ${result}[0]  400
  ${result} =  Controller Post  /savesymbols  [{"name": "DYN_HELLO"}]
  Should Be Equal As Integers  ${result}[0]  400
  ${result} =  Controller Post  /savesymbols
  Should Be Equal As Integers  ${result}[0]  400
  Module Should Have No Overrides  scores
  Module Should Have No Overrides  actions

Reset restores the static values
  ${result} =  Controller Post  /saveactions  [300, null, 90, null]
  Should Be Equal As Integers  ${result}[0]  200
  Wait Until Keyword Succeeds  20x  0.5s  Required Score Should Be Seen By All Workers  300
  ${result} =  Controller Post  /plugins/dynconf/reset?module=actions
  Should Be Equal As Integers  ${result}[0]  200
  Wait Until Keyword Succeeds  20x  0.5s  Required Score Should Be Seen By All Workers  100
  Module Should Have No Overrides  actions

Controller rejects what the subscribers refuse
  ${result} =  Controller Post  /plugins/dynconf/set?module=scores  {"NO_SUCH_SYMBOL": 5}
  Should Be Equal As Integers  ${result}[0]  400
  Should Contain  ${result}[1]  unknown symbol
  ${result} =  Controller Post  /plugins/dynconf/set?module=actions  {"no_such_action": 5}
  Should Be Equal As Integers  ${result}[0]  400
  ${result} =  Controller Post  /plugins/dynconf/set?module=scores  {"DYN_HELLO": "high"}
  Should Be Equal As Integers  ${result}[0]  400
  ${result} =  Controller Post  /plugins/dynconf/set?module=symbols  {"DYN_HELLO": {"enabled": "no"}}
  Should Be Equal As Integers  ${result}[0]  400
  Module Should Have No Overrides  scores
  Module Should Have No Overrides  actions
  Module Should Have No Overrides  symbols

Other modules do not accept overrides by default
  ${result} =  Controller Post  /plugins/dynconf/set?module=regexp  {"x": 1}
  Should Not Be Equal As Integers  ${result}[0]  200

Symbol can be switched off at runtime and on again
  Scan Message
  Expect Symbol  DYN_WORLD
  ${result} =  Controller Post  /plugins/dynconf/set?module=symbols  {"DYN_WORLD": {"enabled": false}}
  Should Be Equal As Integers  ${result}[0]  200
  Wait Until Keyword Succeeds  20x  0.5s  Symbol Should Be Absent For All Workers  DYN_WORLD
  Expect Symbol  DYN_HELLO
  ${result} =  Controller Post  /plugins/dynconf/reset?module=symbols
  Should Be Equal As Integers  ${result}[0]  200
  Wait Until Keyword Succeeds  20x  0.5s  Symbol Should Be Present For All Workers  DYN_WORLD

Disabled symbol stays disabled after a restart
  ${result} =  Controller Post  /plugins/dynconf/set?module=symbols  {"DYN_WORLD": {"enabled": false}}
  Should Be Equal As Integers  ${result}[0]  200
  Restart Rspamd
  Scan Message
  Do Not Expect Symbol  DYN_WORLD
  Expect Symbol  DYN_HELLO
  ${result} =  Controller Post  /plugins/dynconf/reset?module=symbols
  Should Be Equal As Integers  ${result}[0]  200
  Wait Until Keyword Succeeds  20x  0.5s  Symbol Should Be Present For All Workers  DYN_WORLD

A cleared score field removes the override of the symbol
  [Documentation]  the WebUI sends null for it, the other edits of the request are not lost
  ${result} =  Controller Post  /savesymbols  [{"name": "DYN_HELLO", "value": 40.0}, {"name": "DYN_WORLD", "value": null}]
  Should Be Equal As Integers  ${result}[0]  200
  Scores Should Reach All Workers  40.0
  ${result} =  Controller Post  /savesymbols  [{"name": "DYN_HELLO", "value": null}]
  Should Be Equal As Integers  ${result}[0]  200
  Scores Should Reach All Workers  2.0
  Module Should Have No Overrides  scores

A cleared action field removes the override whether or not the action has a static threshold
  [Documentation]  null has one meaning: the action goes back to its static state (to none, if it has no
  ...              static threshold); there is no dynamic way to disable an action
  ${result} =  Controller Post  /saveactions  [250, 8, 65, null]
  Should Be Equal As Integers  ${result}[0]  200
  Wait Until Keyword Succeeds  20x  0.5s  Required Score Should Be Seen By All Workers  250
  ${dump} =  Dump Module  actions
  Should Be Equal As Numbers  ${dump}[modules][actions][overrides][file][values][reject]  250
  Should Be Equal As Numbers  ${dump}[modules][actions][overrides][file][values][rewrite subject]  8
  Should Be Equal As Numbers  ${dump}[modules][actions][overrides][file][values][add header]  65
  ${result} =  Controller Post  /saveactions  [null, null, 65, null]
  Should Be Equal As Integers  ${result}[0]  200
  Wait Until Keyword Succeeds  20x  0.5s  Required Score Should Be Seen By All Workers  100
  ${dump} =  Dump Module  actions
  Should Be Equal As Numbers  ${dump}[modules][actions][overrides][file][values][add header]  65
  Should Not Contain  ${dump}[modules][actions][overrides][file][values]  reject
  Should Not Contain  ${dump}[modules][actions][overrides][file][values]  rewrite subject
  ${result} =  Controller Post  /saveactions  [null, null, null, null]
  Should Be Equal As Integers  ${result}[0]  200
  Module Should Have No Overrides  actions

An action override with the underscore spelling is changed and reset by the WebUI
  ${result} =  Controller Post  /plugins/dynconf/set?module=actions  {"add_header": 61}
  Should Be Equal As Integers  ${result}[0]  200
  ${result} =  Controller Post  /saveactions  [null, null, 62, null]
  Should Be Equal As Integers  ${result}[0]  200
  ${dump} =  Dump Module  actions
  Should Be Equal As Numbers  ${dump}[modules][actions][overrides][file][values][add header]  62
  Should Not Contain  ${dump}[modules][actions][overrides][file][values]  add_header
  ${result} =  Controller Post  /plugins/dynconf/set?module=actions  {"add_header": 61}
  Should Be Equal As Integers  ${result}[0]  200
  ${result} =  Controller Post  /saveactions  [null, null, 30, null]
  Should Be Equal As Integers  ${result}[0]  200
  Module Should Have No Overrides  actions

A composite that is switched off does not strip its atoms
  Scan Composite Message
  Expect Symbol With Score  DYN_AB  5.0
  Do Not Expect Symbol  DYN_CA
  ${result} =  Controller Post  /plugins/dynconf/set?module=symbols  {"DYN_AB": {"enabled": false}}
  Should Be Equal As Integers  ${result}[0]  200
  Wait Until Keyword Succeeds  20x  0.5s  Scan Several Times  Composite Should Be Off
  ${result} =  Controller Post  /plugins/dynconf/reset?module=symbols
  Should Be Equal As Integers  ${result}[0]  200
  Wait Until Keyword Succeeds  20x  0.5s  Scan Several Times  Composite Should Be On

*** Keywords ***
Scan Message
  Scan File  ${MESSAGE}

Scan Composite Message
  Scan File  ${MESSAGE_COMPOSITE}

Composite Should Be Off
  Scan Composite Message
  Do Not Expect Symbol  DYN_AB
  Expect Symbol With Score  DYN_CA  1.0
  Expect Symbol With Score  DYN_CB  1.0

Composite Should Be On
  Scan Composite Message
  Expect Symbol With Score  DYN_AB  5.0
  Do Not Expect Symbol  DYN_CA

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

Controller Should Show
  [Documentation]  the override of `key` is in the dump of the controller (it read the file itself)
  [Arguments]  ${module}  ${key}
  ${dump} =  Dump Module  ${module}
  Dictionary Should Contain Key  ${dump}[modules][${module}][overrides][file][values]  ${key}

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

Symbol Should Be Absent
  [Arguments]  ${symbol}
  Scan Message
  Do Not Expect Symbol  ${symbol}

Symbol Should Be Absent For All Workers
  [Arguments]  ${symbol}
  Scan Several Times  Symbol Should Be Absent  ${symbol}

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
