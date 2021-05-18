*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${MESSAGE}            ${RSPAMD_TESTDIR}/messages/spam_message.eml
${SETTINGS_DNS}       {symbols_enabled = [SIMPLE_DNS, SIMPLE_DNS_SYNC]}

*** Test Cases ***
Simple DNS request
  Scan File  ${MESSAGE}  To-Resolve=example.com
  ...  Settings=${SETTINGS_DNS}
  Expect Symbol With Exact Options  DNS_SYNC  93.184.216.34
  Expect Symbol With Exact Options  DNS  93.184.216.34

Faulty DNS request
  Scan File  ${MESSAGE}  To-Resolve=not-resolvable.com
  ...  Settings=${SETTINGS_DNS}
  Expect Symbol With Exact Options  DNS_SYNC_ERROR  requested record is not found
  Expect Symbol With Exact Options  DNS_ERROR  requested record is not found
