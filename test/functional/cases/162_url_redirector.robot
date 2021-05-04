*** Settings ***
Suite Setup     Urlredirector Setup
Suite Teardown  Urlredirector Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/url_redirector.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/redir.eml
${REDIS_SCOPE}     Suite
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../../contrib/publicsuffix/effective_tld_names.dat
${SETTINGS}        {symbols_enabled=[URL_REDIRECTOR_CHECK]}

*** Test Cases ***
RESOLVE URLS
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

RESOLVE URLS CACHED
  Stop Dummy Http
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

*** Keywords ***
Urlredirector Setup
  Run Dummy Http
  Rspamd Redis Setup

Urlredirector Teardown
  Rspamd Redis Teardown
  #Stop Dummy Http
  Terminate All Processes    kill=True

Stop Dummy Http
  ${http_pid} =  Get File  /tmp/dummy_http.pid
  Shutdown Process With Children  ${http_pid}

Run Dummy Http
  ${result} =  Start Process  ${RSPAMD_TESTDIR}/util/dummy_http.py
  Wait Until Created  /tmp/dummy_http.pid
