*** Settings ***
Test Setup      Regex Setup
Test Teardown   Regex Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/plugins.conf
${MESSAGE}      ${TESTDIR}/messages/newlines.eml
${UTF_MESSAGE}  ${TESTDIR}/messages/utf.eml
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat
${RSPAMD_SCOPE}  Test


*** Test Cases ***
Newlines 
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  SA_BODY_WORD
  Check Rspamc  ${result}  SA_BODY_WORD_WITH_SPACE
  Check Rspamc  ${result}  SA_BODY_WORD_WITH_NEWLINE  inverse=true
  Check Rspamc  ${result}  SA_BODY_WORD_WITH_SPACE_BOUNDARIES
  Check Rspamc  ${result}  SA_BODY_WORD_WITH_SPACE_BOUNDARIES_2
  Check Rspamc  ${result}  SA_BODY_WORD_WITH_SPACE_BOUNDARIES_3
  Check Rspamc  ${result}  SA_BODY_WORD_WITH_SPACE_AND_DOT
  Check Rspamc  ${result}  https://google.com/maps/
  Check Rspamc  ${result}  https://www.google.com/search?q\=hello world&oq\=hello world&aqs\=chrome..69i57j0l5.3045j0j7&sourceid\=chrome&ie\=UTF-8
  Check Rspamc  ${result}  https://github.com/google/sanitizers/wiki/AddressSanitizer


*** Keywords ***
Regex Setup
  ${PLUGIN_CONFIG} =  Get File  ${TESTDIR}/configs/regexp.conf
  Set Suite Variable  ${PLUGIN_CONFIG}
  Generic Setup  PLUGIN_CONFIG

Regex Teardown
  Normal Teardown
