*** Settings ***
Suite Setup     Http Map Expiry Setup
Suite Teardown  Http Map Expiry Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Test Tags       notparallel
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}                     ${RSPAMD_TESTDIR}/configs/lua_test.conf
${MESSAGE}                    ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_LUA_SCRIPT}          ${RSPAMD_TESTDIR}/lua/http_map_expiry.lua
${RSPAMD_MAP_WATCH_INTERVAL}  1s
${RSPAMD_SCOPE}               Suite
${RSPAMD_URL_TLD}             ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${SETTINGS}                   {symbols_enabled = [HTTP_MAP_EXPIRY]}

*** Test Cases ***
BOTH URLS ARE LOADED
  Wait Until Keyword Succeeds  30x  0.5s  Check Both URLs

EXPIRED URL IS REVALIDATED WHILE ANOTHER URL KEEPS CHANGING
  [Documentation]  The first URL has no validators, so each check of it
  ...  reports a change. That must not keep the second URL from being asked
  ...  once its own expiry has passed: it used to be read from the cache
  ...  with the expiry in the past forever, which also made the map poll the
  ...  first URL at the minimum interval.
  Wait Until Keyword Succeeds  30x  1s  Check Expiring URL Is Revalidated

MAP IS INTACT AFTER THE REVALIDATION
  Check Both URLs

*** Keywords ***
Http Map Expiry Setup
  Run Dummy Http
  Rspamd Setup

Http Map Expiry Teardown
  Rspamd Teardown
  Dummy Http Teardown
  Terminate All Processes    kill=True

Check Both URLs
  Scan File  ${MESSAGE}  Settings=${SETTINGS}
  Expect Symbol With Exact Options  HTTP_MAP_EXPIRY  both

Check Expiring URL Is Revalidated
  ${log} =  Get File  ${DUMMY_HTTP_LOG}
  Should Contain  ${log}  /map-expiring is revalidated
