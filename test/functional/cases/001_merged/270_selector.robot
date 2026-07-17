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

From selector orig flavour
  [Documentation]  from('mime', 'orig') must return the wire From through the
  ...  selector pipeline even after a task:set_from rewrite
  Scan File  ${RSPAMD_TESTDIR}/messages/from/from_dn.eml
  ...  Rewrite-Mime-From=yes
  ...  Settings={symbols_enabled = [REWRITE_MIME_FROM, SELECTOR_FROM_ORIG]}
  Expect Symbol With Exact Options  SELECTOR_FROM_ORIG  forged@forged.example.net|user@example.org
