*** Settings ***
Suite Setup     Exporters Setup
Suite Teardown  Exporters Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Library         ${RSPAMD_TESTDIR}/lib/multistage_exporters.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}             ${RSPAMD_TESTDIR}/configs/multistage_exporters.conf
${RSPAMD_LUA_SCRIPT}  ${RSPAMD_TESTDIR}/lua/multistage.lua
${RSPAMD_SCOPE}       Suite
${REDIS_SCOPE}        Suite
${RSPAMD_URL_TLD}     ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
Terminal Exports And EOM Are Counted Once
  [Template]  Multistage Exports
  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}  ${RSPAMD_REDIS_ADDR}  ${RSPAMD_REDIS_PORT}
  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER_SSL}  ${RSPAMD_REDIS_ADDR}  ${RSPAMD_REDIS_PORT}

Exporter Failure Preserves The Frozen Decision
  Multistage Export Failure  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}

*** Keywords ***
Exporters Setup
  Run Redis
  Start Export Collector  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_DUMMY_HTTP}
  Rspamd Setup

Exporters Teardown
  Rspamd Teardown
  Stop Export Collector
  Redis Teardown
