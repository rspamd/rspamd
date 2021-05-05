*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/phishing.conf
${MESSAGE1}        ${RSPAMD_TESTDIR}/messages/phishing1.eml
${MESSAGE2}        ${RSPAMD_TESTDIR}/messages/phishing2.eml
${MESSAGE3}        ${RSPAMD_TESTDIR}/messages/phishing3.eml
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../../contrib/publicsuffix/effective_tld_names.dat

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
