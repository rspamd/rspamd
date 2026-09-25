*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Library         ${RSPAMD_TESTDIR}/lib/multistage.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}             ${RSPAMD_TESTDIR}/configs/multistage.conf
${RSPAMD_LUA_SCRIPT}  ${RSPAMD_TESTDIR}/lua/multistage.lua
${RSPAMD_SCOPE}       Suite
${RSPAMD_URL_TLD}     ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
Self Scan DATA
  [Template]  Multistage Transaction
  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}  continue
  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}  reject
  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}  defer
  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}  async
  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}  timeout
  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}  abort
  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}  no_data

Remote DATA
  [Template]  Multistage Transaction
  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER_SSL}  continue
  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER_SSL}  reject
  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER_SSL}  defer
  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER_SSL}  async
  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER_SSL}  timeout
  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER_SSL}  abort
  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER_SSL}  no_data

Unauthenticated And Lost Responses Fall Back To EOM
  [Template]  Multistage Fallback
  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL_SSL}  ${RSPAMD_PORT_DUMMY_HTTP}  ${RSPAMD_PORT_NORMAL}  wrong_key
  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL_SSL}  ${RSPAMD_PORT_DUMMY_HTTP}  ${RSPAMD_PORT_NORMAL}  disconnect

Scanner Authenticates DATA
  Multistage Authentication  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}

One Terminal Scan Per Transaction
  [Template]  Multistage Accounting
  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}  ${RSPAMD_PORT_CONTROLLER}  continue
  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}  ${RSPAMD_PORT_CONTROLLER}  reject
  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}  ${RSPAMD_PORT_CONTROLLER}  defer
  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER_SSL}  ${RSPAMD_PORT_CONTROLLER}  continue
  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER_SSL}  ${RSPAMD_PORT_CONTROLLER}  reject
  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER_SSL}  ${RSPAMD_PORT_CONTROLLER}  defer
