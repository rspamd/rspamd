*** Settings ***
Test Setup      Rspamd Setup
Test Teardown   Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/regexp.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/newlines.eml
${RSPAMD_SCOPE}    Test
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${UTF_MESSAGE}     ${RSPAMD_TESTDIR}/messages/utf.eml


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

Dynamic Config
  Scan File  ${MESSAGE}
  Expect Symbol With Score  SA_BODY_WORD  10
  Expect Required Score  20
