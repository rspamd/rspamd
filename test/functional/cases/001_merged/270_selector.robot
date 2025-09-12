*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/subject1.eml
${MSG_SPAM}        ${RSPAMD_TESTDIR}/messages/spam_message.eml
${MSG_URL1}        ${RSPAMD_TESTDIR}/messages/url1.eml

*** Test Cases ***
Newlines
  Scan File  ${MESSAGE}  User=test@user.com  Pass=all
  ...  Settings={symbols_enabled = [CONFIG_SELECTOR_RE_RCPT_SUBJECT, LUA_SELECTOR_RE]}
  Expect Symbol  CONFIG_SELECTOR_RE_RCPT_SUBJECT
  Expect Symbol  LUA_SELECTOR_RE

Rspamd_text selector
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [RSPAMD_TEXT_SELECTOR]}
  Expect Symbol  RSPAMD_TEXT_SELECTOR
