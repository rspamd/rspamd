*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}                ${RSPAMD_TESTDIR}/configs/milter_headers.conf
${MESSAGE}               ${RSPAMD_TESTDIR}/messages/zip.eml
${RSPAMD_SCOPE}          Suite
${RSPAMD_URL_TLD}        ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${SETTINGS_NOSYMBOLS}    {symbols_enabled = []}
${SETTINGS_TEST}         {SIMPLE_TEST = 2.0, symbols_enabled = [SIMPLE_TEST]}

*** Test Cases ***
CHECK HEADERS WITH TEST SYMBOL
  Scan File  ${MESSAGE}  Settings=${SETTINGS_TEST}
  # Check X-Virus header
  Expect Removed Header  X-Virus
  Expect Added Header  X-Virus  Fires always
  # Check My-Spamd-Bar header
  Expect Added Header  My-Spamd-Bar  ++
  Do Not Expect Removed Header  My-Spamd-Bar
  # Check X-Spam-Level header
  Expect Added Header  X-Spam-Level  **
  Expect Removed Header  X-Spam-Level

CHECK HEADERS WITHOUT TEST SYMBOL
  Scan File  ${MESSAGE}  Settings=${SETTINGS_NOSYMBOLS}
  # Check X-Virus header
  Expect Removed Header  X-Virus
  Do Not Expect Added Header  X-Virus
  # Check My-Spamd-Bar header
  Expect Added Header  My-Spamd-Bar  /
  Do Not Expect Removed Header  My-Spamd-Bar
  # Check X-Spam-Level header
  Do Not Expect Added Header  X-Spam-Level
  Expect Removed Header  X-Spam-Level
