*** Settings ***
Suite Setup     Urlredirector Setup
Suite Teardown  Urlredirector Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Test Tags       notparallel
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
  Expect Extended URL  http://127.0.0.1:${RSPAMD_PORT_DUMMY_HTTP}/hello

RESOLVE URLS CACHED
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:${RSPAMD_PORT_DUMMY_HTTP}/hello

STEALTH FINGERPRINT HEADERS
  # The live HEAD requests issued by RESOLVE URLS are logged by the dummy
  # HTTP server together with their request headers. Verify the redirector
  # sends a coherent browser fingerprint (not just a bare User-Agent) and
  # that the header order chosen by the profile is preserved on the wire.
  ${log} =  Get File  ${DUMMY_HTTP_LOG}
  Should Contain  ${log}  Sec-Fetch-Mode
  Should Match Regexp  ${log}  HEAD [^\n]*headers: [^\n]*Accept[^\n]*Sec-Fetch-Mode

*** Keywords ***
Urlredirector Setup
  Run Dummy Http
  Rspamd Redis Setup
  # .eml fixtures carry the dummy_http port as a ${RSPAMD_PORT_DUMMY_HTTP}
  # placeholder; render them now that RSPAMD_TMPDIR exists so the per-worker
  # offset is baked into the message the scanner reads.
  ${MESSAGE} =  Render Message Template  ${MESSAGE}
  Set Suite Variable  ${MESSAGE}
  ${CHAIN_MESSAGE} =  Render Message Template  ${CHAIN_MESSAGE}
  Set Suite Variable  ${CHAIN_MESSAGE}

Urlredirector Teardown
  Rspamd Redis Teardown
  Dummy Http Teardown
  Terminate All Processes    kill=True
