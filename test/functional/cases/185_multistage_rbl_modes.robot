*** Settings ***
Test Setup      RBL Setup
Test Teardown   RBL Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Library         ${RSPAMD_TESTDIR}/lib/multistage_rbl.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}             ${RSPAMD_TESTDIR}/configs/multistage_rbl.conf
${RSPAMD_LUA_SCRIPT}  ${RSPAMD_TESTDIR}/lua/multistage_rbl.lua
${RSPAMD_SCOPE}       Test
${RSPAMD_URL_TLD}     ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${RSPAMD_RBL_RELAY_PLUGIN}  disabled
${RSPAMD_RBL_SELECTOR_WHITE}  disabled
${RSPAMD_RBL_RESOLVE_IP}  disabled

*** Test Cases ***
External Relay Defers RBL Envelope Sources
  [Setup]  RBL Mode Setup  RSPAMD_RBL_RELAY_PLUGIN
  Multistage RBL Relay  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}
  Multistage RBL Relay  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER_SSL}

Selector Whitelist Defers Dependent Envelope Checks
  [Setup]  RBL Mode Setup  RSPAMD_RBL_SELECTOR_WHITE
  Multistage RBL Selector White  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}
  Multistage RBL Selector White  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER_SSL}

Resolved IP Queries Preserve All Source Labels
  [Setup]  RBL Mode Setup  RSPAMD_RBL_RESOLVE_IP
  Multistage RBL Resolved  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}
  Multistage RBL Resolved  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER_SSL}

*** Keywords ***
RBL Setup
  Start RBL DNS  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_DUMMY_UDP}
  Rspamd Setup

RBL Mode Setup
  [Arguments]  ${variable}
  Set Test Variable  \${${variable}}  enabled
  RBL Setup

RBL Teardown
  Rspamd Teardown
  Stop RBL DNS
