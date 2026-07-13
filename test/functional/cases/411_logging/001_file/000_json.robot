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
  # robot-save/rspamd.log.last is the global "last run" file and can
  # be overwritten by another pabot worker's teardown between us
  # writing it and reading it. Read the per-suite/per-test copy.
  Check JSON Log  ${EXECDIR}/robot-save/${SUITE_NAME}/${TEST_NAME}/rspamd.log
