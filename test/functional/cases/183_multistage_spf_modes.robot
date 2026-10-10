*** Settings ***
Test Setup      Rspamd Setup
Test Teardown   Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Library         ${RSPAMD_TESTDIR}/lib/multistage_spf.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}             ${RSPAMD_TESTDIR}/configs/multistage_spf.conf
${RSPAMD_LUA_SCRIPT}  ${RSPAMD_TESTDIR}/lua/multistage_spf.lua
${RSPAMD_SCOPE}       Test
${RSPAMD_URL_TLD}     ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${RSPAMD_SPF_EXTERNAL_RELAY}  1
${RSPAMD_SPF_CACHE_SIZE}  0
${RSPAMD_SPF_RELAY_PLUGIN}  disabled

*** Test Cases ***
Received-Based SPF Remains At EOM
  Multistage SPF Record  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}  sender@pass.example.com  ${FALSE}
  Multistage SPF External Relay  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}
  Multistage SPF External Relay  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER_SSL}

Cached SPF Restores Raw Record And Options
  [Setup]  Cached SPF Setup
  Multistage SPF Cached  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}  ${RSPAMD_PORT_DUMMY_UDP}
  Multistage SPF Cached  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER_SSL}  ${RSPAMD_PORT_DUMMY_UDP}

External Relay Plugin Defers SPF And Early Policy
  [Setup]  Relay Plugin Setup  enabled
  Multistage SPF Relay Plugin  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}
  Multistage SPF Relay Plugin  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER_SSL}
  Multistage SPF Record  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}  sender@pass.example.com  ${FALSE}

Disabled Relay Plugin Keeps SPF At DATA
  [Setup]  Relay Plugin Setup  disabled
  SPF Without Relay Rules

Empty Relay Plugin Keeps SPF At DATA
  [Setup]  Relay Plugin Setup  empty
  SPF Without Relay Rules

*** Keywords ***
Cached SPF Setup
  Set Test Variable  ${RSPAMD_SPF_EXTERNAL_RELAY}  0
  Set Test Variable  ${RSPAMD_SPF_CACHE_SIZE}  16
  Rspamd Setup

Relay Plugin Setup
  [Arguments]  ${mode}
  Set Test Variable  ${RSPAMD_SPF_EXTERNAL_RELAY}  0
  Set Test Variable  ${RSPAMD_SPF_RELAY_PLUGIN}  ${mode}
  Rspamd Setup

SPF Without Relay Rules
  Multistage SPF Record  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}
  Multistage SPF Parity  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}  pass.example.com  pass  R_SPF_ALLOW
  Multistage SPF Parity  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER_SSL}  pass.example.com  pass  R_SPF_ALLOW
