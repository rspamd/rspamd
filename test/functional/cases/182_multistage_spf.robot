*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Library         ${RSPAMD_TESTDIR}/lib/multistage_spf.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}             ${RSPAMD_TESTDIR}/configs/multistage_spf.conf
${RSPAMD_LUA_SCRIPT}  ${RSPAMD_TESTDIR}/lua/multistage_spf.lua
${RSPAMD_SCOPE}       Suite
${RSPAMD_URL_TLD}     ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${RSPAMD_SPF_EXTERNAL_RELAY}  0
${RSPAMD_SPF_CACHE_SIZE}  0
${RSPAMD_SPF_RELAY_PLUGIN}  disabled

*** Test Cases ***
SPF Self Scan Parity
  SPF Parity Matrix  ${RSPAMD_PORT_PROXY}

SPF Remote Parity
  SPF Parity Matrix  ${RSPAMD_PORT_CONTROLLER_SSL}

SPF Facts And Results Are Exported
  Multistage SPF Record  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}

SPF Callback Error Discards Partial Results
  Multistage SPF Record  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}  callback-error@pass.example.com  ${FALSE}

SPF Rejects Invalid Typed Facts Before Restoring State
  Multistage SPF Invalid Facts  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}

SPF Explicit Early Rejection
  Multistage SPF Early Reject  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}
  Multistage SPF Early Reject  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER_SSL}

*** Keywords ***
SPF Parity Matrix
  [Arguments]  ${port}
  Multistage SPF Parity  ${RSPAMD_LOCAL_ADDR}  ${port}  pass.example.com  pass  R_SPF_ALLOW
  Multistage SPF Parity  ${RSPAMD_LOCAL_ADDR}  ${port}  fail.example.com  fail  R_SPF_FAIL
  Multistage SPF Parity  ${RSPAMD_LOCAL_ADDR}  ${port}  soft.example.com  softfail  R_SPF_SOFTFAIL
  Multistage SPF Parity  ${RSPAMD_LOCAL_ADDR}  ${port}  neutral.example.com  neutral  R_SPF_NEUTRAL
  Multistage SPF Parity  ${RSPAMD_LOCAL_ADDR}  ${port}  plus.example.com  pass  R_SPF_PLUSALL
  Multistage SPF Parity  ${RSPAMD_LOCAL_ADDR}  ${port}  none.example.com  none  R_SPF_NA
  Multistage SPF Parity  ${RSPAMD_LOCAL_ADDR}  ${port}  temp.example.com  temperror  R_SPF_DNSFAIL
  Multistage SPF Parity  ${RSPAMD_LOCAL_ADDR}  ${port}  perm.example.com  permerror  R_SPF_PERMFAIL
  Multistage SPF Parity  ${RSPAMD_LOCAL_ADDR}  ${port}  pass.example.com  pass  R_SPF_ALLOW  ip=2001:db8::1
  Multistage SPF Parity  ${RSPAMD_LOCAL_ADDR}  ${port}  pass.example.com  pass  R_SPF_ALLOW  sender=${EMPTY}
  Multistage SPF Parity  ${RSPAMD_LOCAL_ADDR}  ${port}  pass.example.com  none  R_SPF_NA  sender=${EMPTY}  helo=[192.0.2.1]
  Multistage SPF Parity  ${RSPAMD_LOCAL_ADDR}  ${port}  pass.example.com  skipped  unused  ip=192.0.2.10
  Multistage SPF Parity  ${RSPAMD_LOCAL_ADDR}  ${port}  pass.example.com  skipped  unused  ip=127.0.0.1
  Multistage SPF Parity  ${RSPAMD_LOCAL_ADDR}  ${port}  pass.example.com  skipped  unused  user=authenticated
  Multistage SPF Parity  ${RSPAMD_LOCAL_ADDR}  ${port}  pass.example.com  fail  R_SPF_FAIL  change=ip  resolves=1
  Multistage SPF Parity  ${RSPAMD_LOCAL_ADDR}  ${port}  pass.example.com  skipped  unused  change=whitelist
  Multistage SPF Parity  ${RSPAMD_LOCAL_ADDR}  ${port}  pass.example.com  skipped  unused  change=disable
  Multistage SPF Parity  ${RSPAMD_LOCAL_ADDR}  ${port}  pass.example.com  pass  R_SPF_ALLOW  change=sender
  Multistage SPF Parity  ${RSPAMD_LOCAL_ADDR}  ${port}  pass.example.com  pass  R_SPF_ALLOW  sender=callback-error@pass.example.com  resolves=1
