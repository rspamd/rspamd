*** Settings ***
Suite Setup     New Setup
Suite Teardown  Simple Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/spamassassin.conf
${RSPAMD_SCOPE}  Suite
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
FREEMAIL
  Scan File  ${TESTDIR}/messages/freemail.eml
  ...  From=faked.asdfjisiwosp372@outlook.com
  Expect Symbol  FREEMAIL_FROM
  Expect Symbol  FREEMAIL_ENVFROM_END_DIGIT
  Expect Symbol  FREEMAIL_SUBJECT
  Expect Symbol  TEST_META4

WLBL WHITELIST
  Scan File  ${TESTDIR}/messages/bad_message.eml
  Expect Symbol  USER_IN_WHITELIST
  Expect Symbol  USER_IN_WHITELIST_TO
  Do Not Expect Symbol  USER_IN_BLACKLIST_TO
  Do Not Expect Symbol  USER_IN_BLACKLIST

WLBL BLACKLIST
  Scan File  ${TESTDIR}/messages/utf.eml
  Expect Symbol  USER_IN_BLACKLIST
  Expect Symbol  USER_IN_BLACKLIST_TO
  Do Not Expect Symbol  USER_IN_WHITELIST_TO
  Do Not Expect Symbol  USER_IN_WHITELIST
