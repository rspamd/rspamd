*** Settings ***
Test Setup      New Setup
Test Teardown   Normal Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/regexp.conf
${MESSAGE}      ${TESTDIR}/messages/newlines.eml
${UTF_MESSAGE}  ${TESTDIR}/messages/utf.eml
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat
${RSPAMD_SCOPE}  Test


*** Test Cases ***
Newlines 
  Scan File  ${MESSAGE}
  Expect Symbol  SA_BODY_WORD
  Expect Symbol  SA_BODY_WORD_WITH_SPACE
  Do Not Expect Symbol  SA_BODY_WORD_WITH_NEWLINE
  Expect Symbol  SA_BODY_WORD_WITH_SPACE_BOUNDARIES
  Expect Symbol  SA_BODY_WORD_WITH_SPACE_BOUNDARIES_2
  Expect Symbol  SA_BODY_WORD_WITH_SPACE_BOUNDARIES_3
  Expect Symbol  SA_BODY_WORD_WITH_SPACE_AND_DOT
  Expect Symbol With Option  FOUND_URL  https://google.com/maps/
  Expect Symbol With Option  FOUND_URL  https://www.google.com/search?q\=hello world&oq\=hello world&aqs\=chrome..69i57j0l5.3045j0j7&sourceid\=chrome&ie\=UTF-8
  Expect Symbol With Option  FOUND_URL  https://github.com/google/sanitizers/wiki/AddressSanitizer
