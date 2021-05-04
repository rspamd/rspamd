*** Settings ***
Suite Setup     Phishing Setup
Suite Teardown  Simple Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}        ${TESTDIR}/configs/phishing.conf
${MESSAGE1}       ${TESTDIR}/messages/phishing1.eml
${MESSAGE2}      ${TESTDIR}/messages/phishing2.eml
${MESSAGE3}      ${TESTDIR}/messages/phishing3.eml
${RSPAMD_SCOPE}  Suite
${URL_TLD}       ${TESTDIR}/../../contrib/publicsuffix/effective_tld_names.dat

*** Test Cases ***
TEST PHISHING
  Scan File  ${MESSAGE1}
  Expect Symbol  PHISHING

TEST PHISHING STRICT ONE
  Scan File  ${MESSAGE2}
  Expect Symbol  STRICT_PHISHING

TEST PHISHING STRICT TWO
  Scan File  ${MESSAGE3}
  Expect Symbol  STRICTER_PHISHING

*** Keywords ***
Phishing Setup
  New Setup  URL_TLD=${URL_TLD}
