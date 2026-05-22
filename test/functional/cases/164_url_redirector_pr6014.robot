*** Settings ***
Suite Setup     Urlredirector PR6014 Setup
Suite Teardown  Urlredirector PR6014 Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}               ${RSPAMD_TESTDIR}/configs/url_redirector_chain.conf
${MESSAGE}              ${RSPAMD_TESTDIR}/messages/redir.eml
${CHAIN_MESSAGE}        ${RSPAMD_TESTDIR}/messages/chain_redirect.eml
${MULTIPART_MESSAGE}    ${RSPAMD_TESTDIR}/messages/chain_multipart.eml
${REDIS_SCOPE}          Suite
${RSPAMD_SCOPE}         Suite
${RSPAMD_URL_TLD}       ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${SETTINGS}    {symbols_enabled=[URL_REDIRECTOR_CHECK]}

*** Test Cases ***
CHAIN REDIRECT RESOLUTION
  [Documentation]  Test PR 6014 feature: resolve redirect chains with intermediate hops
  ...              Tests /redirect2 -> /redirect1 -> /hello chain
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

CHAIN REDIRECT WITH SYMBOL
  [Documentation]  Test that redirector_symbol shows the full redirect path (host1->host2->...->hostN)
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

CHAIN REDIRECT CACHED RESOLUTION
  [Documentation]  Test that cached chain resolution works correctly on second scan
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

REDIRECT CYCLE DETECTION
  [Documentation]  Test cycle detection with /redirect3 <-> /redirect4 cycle
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}

NESTED LIMIT HANDLING
  [Documentation]  Test ^nested: marker behavior when nested_limit is exceeded
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

TIMEOUT CONFIGURATION
  [Documentation]  Test that timeout, http_timeout, and redis_timeout are correctly applied
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

SAVE INTERMEDIATE REDIRS
  [Documentation]  Test save_intermediate_redirs = {redirectors=false, non_redirectors=true}
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

BASIC URL RESOLUTION
  [Documentation]  Test basic URL resolution without redirects
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

*** Keywords ***
Urlredirector PR6014 Setup
  Run Dummy Http
  Rspamd Redis Setup

Urlredirector PR6014 Teardown
  Rspamd Redis Teardown
  Dummy Http Teardown
  Terminate All Processes    kill=True
