*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Systemd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}                         ${RSPAMD_TESTDIR}/configs/systemd.conf
${RSPAMD_SCOPE}                   Suite

*** Test Cases ***
EMPTY TEST
  Pass Execution  No worries

*** Keywords ***
Systemd Teardown
  Touch  ${RSPAMD_TMPDIR}/rspamd.log
  Rspamd Teardown
  ${log} =  Get File  ${EXECDIR}/robot-save/rspamd.stderr.last
  Should Match Regexp  ${log}  \\n\\(main\\) lua; lua_cfg_transform\\.lua:\\d+: overriding actions from the legacy metric settings\\n
