*** Settings ***
Documentation    Import of the file of the previous dynamic configuration (`options { dynamic_conf }`): the
...              overrides in it are stored in dynconf once by the primary controller, apply to every scanning
...              worker, and the file is renamed so that it is never imported again.
Suite Setup      Legacy Setup
Suite Teardown   Rspamd Teardown
Library          Process
Library          OperatingSystem
Library          ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource         ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables        ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}               ${RSPAMD_TESTDIR}/configs/dynconf_legacy_file.conf
${RSPAMD_SCOPE}         Suite
${RSPAMD_URL_TLD}       ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${MESSAGE}              ${RSPAMD_TESTDIR}/messages/dynconf_hello.eml
${LEGACY_FILE_CONTENT}  [{"metric": "default", "symbols": [{"name": "DYN_HELLO", "value": 40.0}, {"name": "NO_SUCH_SYMBOL", "value": 5.0}, {"name": "DYN_WORLD", "value": 3.0}], "actions": [{"name": "reject", "value": 200.0}, {"name": "add_header", "value": 25.0}, {"name": "greylist", "value": null}, {"name": "rewrite_subject", "value": 70.0}]}]

*** Test Cases ***
Legacy overrides are imported and apply to every worker
  [Documentation]  DYN_WORLD has the static score already (3.0), `greylist` is null: both are left out
  Scores Should Reach All Workers  40.0
  Wait Until Keyword Succeeds  20x  0.5s  Required Score Should Be Seen By All Workers  200
  Expect Action  add header
  ${dump} =  Dump Module  scores
  Should Be Equal As Numbers  ${dump}[modules][scores][overrides][file][values][DYN_HELLO]  40.0
  Should Not Contain  ${dump}[modules][scores][overrides][file][values]  NO_SUCH_SYMBOL
  Should Not Contain  ${dump}[modules][scores][overrides][file][values]  DYN_WORLD
  ${dump} =  Dump Module  actions
  Should Be Equal As Numbers  ${dump}[modules][actions][overrides][file][values][reject]  200
  Should Be Equal As Numbers  ${dump}[modules][actions][overrides][file][values][add header]  25
  Should Not Contain  ${dump}[modules][actions][overrides][file][values]  greylist

An entry that override.d defines is left out and does not fail the import
  [Documentation]  rewrite subject has the priority 10: a write of it would be refused, so it is not imported
  ...              (and the scores, the actions and the rename of the file do not depend on it)
  ${dump} =  Dump Module  actions
  Should Not Contain  ${dump}[modules][actions][overrides][file][values]  rewrite subject
  Should Not Contain  ${dump}[modules][actions][overrides][file][values]  rewrite_subject
  Log Should Contain  skipped the threshold of the action rewrite subject is defined with a higher priority

The legacy file is renamed
  File Should Not Exist  ${RSPAMD_TMPDIR}/rspamd_dynamic
  File Should Exist  ${RSPAMD_TMPDIR}/rspamd_dynamic.imported
  File Should Exist  ${RSPAMD_TMPDIR}/rspamd_dynconf.json

The import is done once
  [Documentation]  After a reset and a restart the old values do not come back: the file is gone
  ${result} =  Controller Post  /plugins/dynconf/reset?module=scores
  Should Be Equal As Integers  ${result}[0]  200
  ${result} =  Controller Post  /plugins/dynconf/reset?module=actions
  Should Be Equal As Integers  ${result}[0]  200
  Restart Rspamd
  Scan Message
  Expect Symbol With Score  DYN_HELLO  2.0
  Expect Required Score  100
  Expect Action  no action
  Module Should Have No Overrides  scores
  Module Should Have No Overrides  actions

A file that is not a legacy configuration is left alone
  [Documentation]  the primary controller finds the overrides of dynconf (none now) and a file it cannot read
  Create File  ${RSPAMD_TMPDIR}/rspamd_dynamic  not a json array
  Restart Rspamd
  Scan Message
  Expect Symbol With Score  DYN_HELLO  2.0
  File Should Exist  ${RSPAMD_TMPDIR}/rspamd_dynamic
  Module Should Have No Overrides  scores

*** Keywords ***
Legacy Setup
  [Documentation]  The legacy file has to exist before rspamd starts
  ${RSPAMD_TMPDIR} =  Make Temporary Directory
  Set Directory Ownership  ${RSPAMD_TMPDIR}  ${RSPAMD_USER}  ${RSPAMD_GROUP}
  Set Suite Variable  ${RSPAMD_TMPDIR}
  Set Global Variable  ${RSPAMD_TMPDIR}
  Create File  ${RSPAMD_TMPDIR}/rspamd_dynamic  ${LEGACY_FILE_CONTENT}
  Run Rspamd

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

Restart Rspamd
  Terminate Process  ${RSPAMD_PROCESS}
  Wait For Process  ${RSPAMD_PROCESS}
  Wait For Rspamd Ports Released
  Run Rspamd

Log Should Contain
  [Arguments]  ${text}
  ${log} =  Get File  ${RSPAMD_TMPDIR}/rspamd.log
  Should Contain  ${log}  ${text}
