*** Settings ***
Suite Setup     RBL Setup
Suite Teardown  RBL Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Library         ${RSPAMD_TESTDIR}/lib/multistage_rbl.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}             ${RSPAMD_TESTDIR}/configs/multistage_rbl.conf
${RSPAMD_LUA_SCRIPT}  ${RSPAMD_TESTDIR}/lua/multistage_rbl.lua
${RSPAMD_SCOPE}       Suite
${RSPAMD_URL_TLD}     ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${RSPAMD_RBL_RELAY_PLUGIN}  disabled

*** Test Cases ***
RBL Mixed Self Scan Parity
  Multistage RBL Parity  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}

RBL Mixed Remote Parity
  Multistage RBL Parity  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER_SSL}

RBL Export Contains Only Audited Envelope Parts
  Multistage RBL Record  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}

RBL Invalid Facts Fall Back Before Results Are Restored
  Multistage RBL Invalid Facts  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}

RBL Explicit Early Policy
  Multistage RBL Early Reject  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}
  Multistage RBL Early Reject  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER_SSL}

RBL Named Settings Preserve Public And Virtual Selection
  Multistage RBL Settings  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}

*** Keywords ***
RBL Setup
  Start RBL DNS  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_DUMMY_UDP}
  Rspamd Setup

RBL Teardown
  Rspamd Teardown
  Stop RBL DNS
