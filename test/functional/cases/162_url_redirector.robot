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
${CHAIN_MESSAGE}   ${RSPAMD_TESTDIR}/messages/chain_redirect.eml
${REDIS_SCOPE}     Suite
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${SETTINGS}        {symbols_enabled=[URL_REDIRECTOR_CHECK]}

*** Test Cases ***
RESOLVE URLS
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

RESOLVE URLS CACHED
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

STEALTH FINGERPRINT HEADERS
  # The live HEAD requests issued by RESOLVE URLS are logged by the dummy
  # HTTP server together with their request headers. Verify the redirector
  # sends a coherent browser fingerprint (not just a bare User-Agent) and
  # that the header order chosen by the profile is preserved on the wire.
  ${log} =  Get File  /tmp/dummy_http.log
  Should Contain  ${log}  Sec-Fetch-Mode
  Should Match Regexp  ${log}  HEAD [^\n]*headers: [^\n]*Accept[^\n]*Sec-Fetch-Mode

*** Keywords ***
Urlredirector Setup
  Run Dummy Http
  Rspamd Redis Setup

Urlredirector Teardown
  Rspamd Redis Teardown
  Dummy Http Teardown
  Terminate All Processes    kill=True
