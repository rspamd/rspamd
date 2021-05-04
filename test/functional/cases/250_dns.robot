*** Settings ***
Test Setup      New Setup
Test Teardown   Normal Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${RSPAMD_LUA_SCRIPT}  ${RSPAMD_TESTDIR}/lua/dns.lua
${RSPAMD_URL_TLD}      ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${CONFIG}       ${RSPAMD_TESTDIR}/configs/lua_test.conf
${MESSAGE}      ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_SCOPE}  Test

*** Test Cases ***
Simple DNS request
  Scan File  ${MESSAGE}  To-Resolve=example.com
  Expect Symbol With Exact Options  DNS_SYNC  93.184.216.34
  Expect Symbol With Exact Options  DNS  93.184.216.34

Faulty DNS request
  Scan File  ${MESSAGE}  To-Resolve=not-resolvable.com
  Expect Symbol With Exact Options  DNS_SYNC_ERROR  requested record is not found
  Expect Symbol With Exact Options  DNS_ERROR  requested record is not found
