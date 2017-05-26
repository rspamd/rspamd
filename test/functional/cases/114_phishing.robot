*** Settings ***
Suite Setup     Phishing Setup
Suite Teardown  Simple Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}        ${TESTDIR}/configs/plugins.conf
${MESSAGE1}       ${TESTDIR}/messages/phishing1.eml
${MESSAGE2}      ${TESTDIR}/messages/phishing2.eml
${MESSAGE3}      ${TESTDIR}/messages/phishing3.eml
${RSPAMD_SCOPE}  Suite
${URL_TLD}       ${TESTDIR}/../../contrib/publicsuffix/effective_tld_names.dat

*** Test Cases ***
TEST PHISHING
  ${result} =  Scan Message With Rspamc  ${MESSAGE1}
  Check Rspamc  ${result}  ${SPACE}PHISHING

TEST PHISHING STRICT ONE
  ${result} =  Scan Message With Rspamc  ${MESSAGE2}
  Check Rspamc  ${result}  STRICT_PHISHING

TEST PHISHING STRICT TWO
  ${result} =  Scan Message With Rspamc  ${MESSAGE3}
  Check Rspamc  ${result}  STRICTER_PHISHING

*** Keywords ***
Phishing Setup
  ${PLUGIN_CONFIG} =  Get File  ${TESTDIR}/configs/phishing.conf
  Set Suite Variable  ${PLUGIN_CONFIG}
  Generic Setup  PLUGIN_CONFIG
