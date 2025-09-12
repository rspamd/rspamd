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

# SA-like regexp_rules: header/body/rawbody/uri/full/selector/meta
SA Header Atom
  Scan File  ${MSG_SPAM}
  ...   Settings={symbols_enabled = [SA_HDR_SUBJ]}
  Expect Symbol  SA_HDR_SUBJ

SA Body Atom
  Scan File  ${MSG_SPAM}
  ...   Settings={symbols_enabled = [SA_BODY_SIMPLE]}
  Expect Symbol  SA_BODY_SIMPLE

SA Rawbody Atom
  Scan File  ${MSG_SPAM}
  ...   Settings={symbols_enabled = [SA_RAW_SIMPLE]}
  Expect Symbol  SA_RAW_SIMPLE

SA URI Atom
  Scan File  ${MSG_URL1}
  ...   Settings={symbols_enabled = [SA_URI_SHORT]}
  Expect Symbol  SA_URI_SHORT

SA Full Atom
  Scan File  ${MSG_SPAM}
  ...   Settings={symbols_enabled = [SA_FULL_BOUNDARY]}
  Expect Symbol  SA_FULL_BOUNDARY

SA Selector Atom (From Domain)
  Scan File  ${MSG_SPAM}
  ...   From=user@example.com
  ...   Settings={symbols_enabled = [SA_SEL_FROM_DOM]}
  Expect Symbol  SA_SEL_FROM_DOM

SA Selector Atom (URL TLD)
  Scan File  ${MSG_URL1}
  ...   Settings={symbols_enabled = [SA_SEL_URL_TLD]}
  Expect Symbol  SA_SEL_URL_TLD

SA Selector Negation
  Scan File  ${MSG_SPAM}
  ...   From=user@example.com
  ...   Settings={symbols_enabled = [SA_SEL_NOT_CORP]}
  Expect Symbol  SA_SEL_NOT_CORP

SA Meta AND
  Scan File  ${MSG_SPAM}
  ...   From=user@example.com
  ...   Settings={symbols_enabled = [SA_META_AND, SA_HDR_SUBJ, SA_BODY_SIMPLE, SA_SEL_FROM_DOM]}
  Expect Symbol  SA_META_AND

SA Meta OR
  Scan File  ${MSG_URL1}
  ...   Settings={symbols_enabled = [SA_META_OR, SA_URI_SHORT, SA_SEL_URL_TLD]}
  Expect Symbol  SA_META_OR

SA Meta Complex
  Scan File  ${MSG_SPAM}
  ...   From=user@example.com
  ...   Settings={symbols_enabled = [SA_META_COMPLEX, SA_RAW_SIMPLE, SA_SEL_NOT_CORP]}
  Expect Symbol  SA_META_COMPLEX
