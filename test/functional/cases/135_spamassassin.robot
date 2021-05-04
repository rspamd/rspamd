*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/spamassassin.conf
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
FREEMAIL
  Scan File  ${RSPAMD_TESTDIR}/messages/freemail.eml
  ...  From=faked.asdfjisiwosp372@outlook.com
  Expect Symbol  FREEMAIL_FROM
  Expect Symbol  FREEMAIL_ENVFROM_END_DIGIT
  Expect Symbol  FREEMAIL_SUBJECT
  Expect Symbol  TEST_META4

WLBL WHITELIST
  Scan File  ${RSPAMD_TESTDIR}/messages/bad_message.eml
  Expect Symbol  USER_IN_WHITELIST
  Expect Symbol  USER_IN_WHITELIST_TO
  Do Not Expect Symbol  USER_IN_BLACKLIST_TO
  Do Not Expect Symbol  USER_IN_BLACKLIST

WLBL BLACKLIST
  Scan File  ${RSPAMD_TESTDIR}/messages/utf.eml
  Expect Symbol  USER_IN_BLACKLIST
  Expect Symbol  USER_IN_BLACKLIST_TO
  Do Not Expect Symbol  USER_IN_WHITELIST_TO
  Do Not Expect Symbol  USER_IN_WHITELIST
