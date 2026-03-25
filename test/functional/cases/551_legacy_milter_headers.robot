*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}             ${RSPAMD_TESTDIR}/configs/milter_headers.conf
${MESSAGE}            ${RSPAMD_TESTDIR}/messages/zip.eml
${RSPAMD_SCOPE}       Suite
${RSPAMD_URL_TLD}     ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
RSPAMC PROTOCOL STATUS LINE
  [Documentation]  Verify RSPAMC response has correct status line and basic structure
  ${result} =  Rspamc  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}  ${MESSAGE}
  Should Contain  ${result}  RSPAMD/1.3 0 EX_OK
  Should Contain  ${result}  Metric: default;

RSPAMC BACKWARD COMPATIBLE SYMBOLS
  [Documentation]  Existing Symbol: lines must be preserved
  ${result} =  Rspamc  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}  ${MESSAGE}
  Should Match Regexp  ${result}  Symbol: SIMPLE_TEST\\(\\d+\\.\\d+\\)

RSPAMC EXTENDED SYMBOLS
  [Documentation]  X-Symbol: lines with options from symbol callbacks
  ${result} =  Rspamc  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}  ${MESSAGE}
  Should Match Regexp  ${result}  X-Symbol: SIMPLE_TEST\\(\\d+\\.\\d+\\).*\\[Fires always\\]

RSPAMC MILTER ADD HEADERS
  [Documentation]  X-Milter-Add: lines for milter add_headers
  ${result} =  Rspamc  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}  ${MESSAGE}
  Should Match Regexp  ${result}  X-Milter-Add: X-Virus:
  Should Match Regexp  ${result}  X-Milter-Add: My-Spamd-Bar:
  Should Match Regexp  ${result}  X-Milter-Add: X-Spam-Level:

RSPAMC MILTER DEL HEADERS
  [Documentation]  X-Milter-Del: lines for milter remove_headers
  ${result} =  Rspamc  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}  ${MESSAGE}
  Should Match Regexp  ${result}  X-Milter-Del: X-Spam-Level
  Should Match Regexp  ${result}  X-Milter-Del: X-Virus

SPAMC PROTOCOL STATUS LINE
  [Documentation]  Verify SPAMC response has correct status line
  ${result} =  Spamc  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}  ${MESSAGE}
  Should Contain  ${result}  SPAMD/1.1 0 EX_OK

SPAMC MILTER ADD HEADERS
  [Documentation]  X-Milter-Add: lines in SPAMC protocol output
  ${result} =  Spamc  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}  ${MESSAGE}
  Should Match Regexp  ${result}  X-Milter-Add: X-Virus:
  Should Match Regexp  ${result}  X-Milter-Add: My-Spamd-Bar:

SPAMC MILTER DEL HEADERS
  [Documentation]  X-Milter-Del: lines in SPAMC protocol output
  ${result} =  Spamc  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}  ${MESSAGE}
  Should Match Regexp  ${result}  X-Milter-Del: X-Spam-Level
  Should Match Regexp  ${result}  X-Milter-Del: X-Virus
