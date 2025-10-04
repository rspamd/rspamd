*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Test Cases ***

# Basic alias resolution tests

UNIX ALIAS - SIMPLE RESOLUTION
  [Documentation]  Test simple Unix alias resolution (postmaster -> root)
  Scan File  ${RSPAMD_TESTDIR}/messages/aliases_simple.eml
  ...  From=sender@external.com
  ...  Rcpt=postmaster@example.com
  Expect Symbol  ALIAS_RESOLVED
  Expect Symbol  LOCAL_INBOUND

PLUS ADDRESSING - BASIC
  [Documentation]  Test basic plus addressing (user+tag@domain)
  Scan File  ${RSPAMD_TESTDIR}/messages/aliases_plus.eml
  ...  From=sender@external.com
  ...  Rcpt=user+tag@example.com
  Expect Symbol  TAGGED_RCPT
  Expect Symbol  LOCAL_INBOUND

# Message classification tests

CLASSIFICATION - INTERNAL MAIL
  [Documentation]  Test internal mail classification (local -> local)
  Scan File  ${RSPAMD_TESTDIR}/messages/aliases_internal.eml
  ...  From=user1@example.com
  ...  Rcpt=user2@example.com
  ...  IP=127.0.0.1
  Expect Symbol  INTERNAL_MAIL
  Do Not Expect Symbol  LOCAL_INBOUND
  Do Not Expect Symbol  LOCAL_OUTBOUND

CLASSIFICATION - OUTBOUND MAIL
  [Documentation]  Test outbound mail classification (local -> external)
  Scan File  ${RSPAMD_TESTDIR}/messages/aliases_outbound.eml
  ...  From=user@example.com
  ...  Rcpt=external@foreign.com
  ...  IP=127.0.0.1
  Expect Symbol  LOCAL_OUTBOUND
  Do Not Expect Symbol  LOCAL_INBOUND
  Do Not Expect Symbol  INTERNAL_MAIL

CLASSIFICATION - INBOUND MAIL
  [Documentation]  Test inbound mail classification (external -> local)
  Scan File  ${RSPAMD_TESTDIR}/messages/aliases_inbound.eml
  ...  From=external@foreign.com
  ...  Rcpt=support@example.com
  Expect Symbol  LOCAL_INBOUND
  Expect Symbol  ALIAS_RESOLVED
  Do Not Expect Symbol  LOCAL_OUTBOUND
  Do Not Expect Symbol  INTERNAL_MAIL

# Gmail-specific tests

GMAIL DOTS REMOVAL
  [Documentation]  Test Gmail dots removal (first.last@gmail.com -> firstlast@gmail.com)
  Scan File  ${RSPAMD_TESTDIR}/messages/spam_message.eml
  ...  From=first.last@gmail.com
  ...  Rcpt=user@example.com
  Expect Symbol  ALIAS_RESOLVED
  # Note: TAGGED_FROM is only for plus-addressing, not for dots removal

GMAIL PLUS ADDRESSING
  [Documentation]  Test Gmail plus addressing (user+tag@gmail.com -> user@gmail.com)
  Scan File  ${RSPAMD_TESTDIR}/messages/spam_message.eml
  ...  From=external@test.com
  ...  Rcpt=user+newsletters@gmail.com
  Expect Symbol  TAGGED_RCPT
  Expect Symbol  ALIAS_RESOLVED

GMAIL DOTS AND PLUS
  [Documentation]  Test Gmail dots + plus addressing combined
  Scan File  ${RSPAMD_TESTDIR}/messages/spam_message.eml
  ...  From=first.last+tag@gmail.com
  ...  Rcpt=user@example.com
  Expect Symbol  TAGGED_FROM
  Expect Symbol  ALIAS_RESOLVED

# Virtual aliases tests

VIRTUAL ALIAS - SIMPLE
  [Documentation]  Test virtual alias resolution (contact@example.com -> support@example.com)
  Scan File  ${RSPAMD_TESTDIR}/messages/spam_message.eml
  ...  From=sender@external.com
  ...  Rcpt=contact@example.com
  Expect Symbol  ALIAS_RESOLVED
  Expect Symbol  LOCAL_INBOUND

# Chained aliases tests

CHAINED ALIAS RESOLUTION
  [Documentation]  Test chained alias resolution (sales -> team-sales -> sales-inbox@example.com)
  Scan File  ${RSPAMD_TESTDIR}/messages/spam_message.eml
  ...  From=customer@external.com
  ...  Rcpt=sales@example.com
  Expect Symbol  ALIAS_RESOLVED
  Expect Symbol  LOCAL_INBOUND

# Rspamd inline aliases tests

RSPAMD INLINE ALIAS
  [Documentation]  Test rspamd inline alias from config (rspamd-alias@example.com)
  Scan File  ${RSPAMD_TESTDIR}/messages/spam_message.eml
  ...  From=sender@external.com
  ...  Rcpt=rspamd-alias@example.com
  Expect Symbol  ALIAS_RESOLVED
  Expect Symbol  LOCAL_INBOUND

# Local domain detection tests

LOCAL DOMAIN - POSITIVE
  [Documentation]  Test local domain detection for example.com
  Scan File  ${RSPAMD_TESTDIR}/messages/spam_message.eml
  ...  From=user@example.com
  ...  Rcpt=other@example.com
  ...  IP=127.0.0.1
  Expect Symbol  INTERNAL_MAIL

LOCAL DOMAIN - SUBDOMAIN
  [Documentation]  Test local domain detection for mail.example.com
  Scan File  ${RSPAMD_TESTDIR}/messages/spam_message.eml
  ...  From=user@mail.example.com
  ...  Rcpt=other@example.com
  ...  IP=127.0.0.1
  Expect Symbol  INTERNAL_MAIL

LOCAL DOMAIN - NEGATIVE
  [Documentation]  Test that external domain is not detected as local
  Scan File  ${RSPAMD_TESTDIR}/messages/spam_message.eml
  ...  From=user@foreign.com
  ...  Rcpt=other@example.com
  Expect Symbol  LOCAL_INBOUND
  Do Not Expect Symbol  INTERNAL_MAIL

# Combined tests

PLUS ADDRESSING WITH ALIAS
  [Documentation]  Test plus addressing combined with alias resolution
  Scan File  ${RSPAMD_TESTDIR}/messages/spam_message.eml
  ...  From=sender@external.com
  ...  Rcpt=support+urgent@example.com
  Expect Symbol  TAGGED_RCPT
  Expect Symbol  ALIAS_RESOLVED

FROM AND RCPT TAGGED
  [Documentation]  Test when both from and recipient have plus tags
  Scan File  ${RSPAMD_TESTDIR}/messages/spam_message.eml
  ...  From=sender+tag@external.com
  ...  Rcpt=user+tag@example.com
  Expect Symbol  TAGGED_FROM
  Expect Symbol  TAGGED_RCPT
