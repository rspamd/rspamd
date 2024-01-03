*** Settings ***
Test Setup      Rspamd Setup
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}                         ${RSPAMD_TESTDIR}/configs/loggingtest.conf
${RSPAMD_LOGGINGTYPE}             file
${RSPAMD_JSON}                    true
${RSPAMD_SYSTEMD}                 true
${RSPAMD_SCOPE}                   Test

*** Test Cases ***
JSON LOGS
  Rspamd Teardown
  Check JSON Log  ${EXECDIR}/robot-save/rspamd.log.last
