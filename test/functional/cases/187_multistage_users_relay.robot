*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Library         ${RSPAMD_TESTDIR}/lib/multistage_users.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}             ${RSPAMD_TESTDIR}/configs/multistage_users.conf
${RSPAMD_LUA_SCRIPT}  ${RSPAMD_TESTDIR}/lua/multistage_users.lua
${RSPAMD_SCOPE}       Suite
${RSPAMD_URL_TLD}     ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${RSPAMD_DATA_RELAY_PLUGIN}  enabled

*** Test Cases ***
External Relay Defers ASN And Its Consumers
  Multistage Users Relay  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}  ${RSPAMD_PORT_NORMAL}
  Multistage Users Relay  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER_SSL}  ${RSPAMD_PORT_NORMAL}
