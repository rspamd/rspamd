*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${MESSAGE1}           ${RSPAMD_TESTDIR}/messages/phishing1.eml
${MESSAGE2}           ${RSPAMD_TESTDIR}/messages/phishing2.eml
${MESSAGE3}           ${RSPAMD_TESTDIR}/messages/phishing3.eml
${SETTINGS_PHISHING}  {symbols_enabled = [PHISHING,STRICT_PHISHING,STRICTER_PHISHING]}

*** Test Cases ***
TEST PHISHING
  Scan File  ${MESSAGE1}
  ...  Settings=${SETTINGS_PHISHING}
  Expect Symbol  PHISHING

TEST PHISHING STRICT ONE
  Scan File  ${MESSAGE2}
  ...  Settings=${SETTINGS_PHISHING}
  Expect Symbol  STRICT_PHISHING

TEST PHISHING STRICT TWO
  Scan File  ${MESSAGE3}
  ...  Settings=${SETTINGS_PHISHING}
  Expect Symbol  STRICTER_PHISHING
