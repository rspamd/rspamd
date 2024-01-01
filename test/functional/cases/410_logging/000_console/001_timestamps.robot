*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Console Timestamps Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}                         ${RSPAMD_TESTDIR}/configs/loggingtest.conf
${RSPAMD_LOGGINGTYPE}             console
${RSPAMD_JSON}                    false
${RSPAMD_SYSTEMD}                 false
${RSPAMD_SCOPE}                   Suite

*** Test Cases ***
EMPTY TEST
  Pass Execution  No worries

*** Keywords ***
Console Timestamps Teardown
  Touch  ${RSPAMD_TMPDIR}/rspamd.log
  Rspamd Teardown
  ${log} =  Get File  ${EXECDIR}/robot-save/rspamd.stderr.last
  Should Match Regexp  ${log}  \\n\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}  #\\d+\\(main\\) lua; lua_cfg_transform\\.lua:\\d+: overriding actions from the legacy metric settings\\n
