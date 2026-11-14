*** Settings ***
Documentation    Dynamic configuration (the file backend): `action = null` of local.d (priority 1) or override.d
...              (priority 10) disables the action with the priority of that file, in either spelling of the
...              action (`add_header`). The one of override.d beats a dynamic threshold, the one of local.d does
...              not, and the disabled state comes back when the override is removed.
Suite Setup      Rspamd Setup
Suite Teardown   Rspamd Teardown
Library          Process
Library          OperatingSystem
Library          ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource         ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables        ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}               ${RSPAMD_TESTDIR}/configs/dynconf_null.conf
${RSPAMD_SCOPE}         Suite
${RSPAMD_URL_TLD}       ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${MESSAGE}              ${RSPAMD_TESTDIR}/messages/dynconf_hello.eml

*** Test Cases ***
A null in override.d disables the action and beats a dynamic threshold
  Log Should Contain  disable action add header; old priority: 0, new priority: 10
  ${result} =  Controller Post  /saveactions  [200, null, 60, null]
  Should Be Equal As Integers  ${result}[0]  500
  Should Contain  ${result}[1]  add header
  Should Contain  ${result}[1]  priority 10
  Should Contain  ${result}[1]  cannot be changed dynamically
  Module Should Have No Overrides  actions
  ${result} =  Controller Post  /plugins/dynconf/set?module=actions  {"add_header": 60}
  Should Be Equal As Integers  ${result}[0]  400
  Should Contain  ${result}[1]  priority 10
  Module Should Have No Overrides  actions

A null in local.d is beaten by a dynamic threshold
  Log Should Contain  disable action greylist; old priority: 0, new priority: 1
  ${result} =  Controller Post  /saveactions  [200, null, null, 7]
  Should Be Equal As Integers  ${result}[0]  200
  Wait Until Keyword Succeeds  20x  0.5s  Required Score Should Be Seen By All Workers  200
  ${dump} =  Dump Module  actions
  Should Be Equal As Numbers  ${dump}[modules][actions][overrides][file][values][greylist]  7
  Should Be Equal As Numbers  ${dump}[modules][actions][overrides][file][values][reject]  200
  Should Not Contain  ${dump}[modules][actions][overrides][file][values]  add header

The disabled state comes back when the override is removed
  ${result} =  Controller Post  /saveactions  [null, null, null, null]
  Should Be Equal As Integers  ${result}[0]  200
  Wait Until Keyword Succeeds  20x  0.5s  Required Score Should Be Seen By All Workers  100
  Module Should Have No Overrides  actions
  Log Should Contain  restore the threshold of the action greylist

*** Keywords ***
Log Should Contain
  [Arguments]  ${text}
  ${log} =  Get File  ${RSPAMD_TMPDIR}/rspamd.log
  Should Contain  ${log}  ${text}

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

Required Score Should Be
  [Arguments]  ${expected}
  Scan Message
  Expect Required Score  ${expected}

Required Score Should Be Seen By All Workers
  [Arguments]  ${expected}
  Scan Several Times  Required Score Should Be  ${expected}
