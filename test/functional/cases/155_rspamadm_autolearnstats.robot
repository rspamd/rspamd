*** Settings ***
Suite Setup     Rspamd Autolearnstats Setup
Suite Teardown  Rspamd Autolearnstats Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py
Test Timeout    1 minute

*** Variables ***
${CONFIG}                 ${RSPAMD_TESTDIR}/configs/autolearnstats_test.conf
${MESSAGE_SPAM}           ${RSPAMD_TESTDIR}/messages/autolearnstats_spam.eml
${MESSAGE_HAM}            ${RSPAMD_TESTDIR}/messages/autolearnstats_ham.eml
${RSPAMD_SCOPE}           Suite

*** Keywords ***
Rspamd Autolearnstats Setup
  Rspamadm Setup
  Rspamd Setup

Rspamd Autolearnstats Teardown
  Rspamd Teardown
  Rspamadm Teardown

*** Test Cases ***
Autolearnstats output
  Scan File  ${MESSAGE_SPAM}
  Scan File  ${MESSAGE_HAM}
  ${result} =  Rspamadm  autolearnstats  ${RSPAMD_TMPDIR}/rspamd.log
  Should Be Equal As Integers  ${result.rc}  0
  Should Match Regexp  ${result.stdout}  \\s+Verd\\s+Score\\s+Timestamp\\s+Task\\s+IP\\s+From\\s+Recipients
  Should Match Regexp  ${result.stdout}  \\[L\\]\\s+spam\\s+16\\.00>=10\\s+\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\s+[a-f0-9]{6}\\s+-\\s+undef\\s+test@example\\.com
  Should Match Regexp  ${result.stdout}  \\[L\\]\\s+ham\\s+-16\\.00<=-10\\s+\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\s+[a-f0-9]{6}\\s+-\\s+undef\\s+test@example\\.com
  Should Match Regexp  ${result.stdout}  Total autolearn candidates: 2\\s+Learned: 2
  Should Match Regexp  ${result.stdout}  ham\\s+1 candidates\\s+[/]\\s+1 learned
  Should Match Regexp  ${result.stdout}  spam\\s+1 candidates\\s+[/]\\s+1 learned$

Autolearnstats stdin
  Scan File  ${MESSAGE_SPAM}
  ${result} =  Run Process  ${RSPAMADM}
  ...  --var\=TMPDIR\=${RSPAMADM_TMPDIR}
  ...  --var\=DBDIR\=${RSPAMADM_TMPDIR}
  ...  --var\=LOCAL_CONFDIR\=/nonexistent
  ...  autolearnstats  -
  ...  stdin=${RSPAMD_TMPDIR}/rspamd.log
  Should Be Equal As Integers  ${result.rc}  0
  Should Match Regexp  ${result.stdout}  Total autolearn candidates: 3\\s+Learned: 3
  Should Match Regexp  ${result.stdout}  ham\\s+1 candidates\\s+[/]\\s+1 learned
  Should Match Regexp  ${result.stdout}  spam\\s+2 candidates\\s+[/]\\s+2 learned$

Autolearnstats time filtering
  Scan File  ${MESSAGE_SPAM}
  ${result} =  Rspamadm  autolearnstats
  ...  --start  "2020-01-01"
  ...  --end  "2020-01-02"
  ...  ${RSPAMD_TMPDIR}/rspamd.log
  Should Be Equal As Integers  ${result.rc}  0
  Should Be Equal  ${result.stdout}  No autolearn candidates found.
