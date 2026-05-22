*** Settings ***
Suite Setup     Urlredirector Config Setup
Suite Teardown  Urlredirector Config Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/url_redirector_no_intermediate.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/redir.eml
${REDIS_SCOPE}     Suite
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${SETTINGS}        {symbols_enabled=[URL_REDIRECTOR_CHECK]}

*** Test Cases ***
SAVE_INTERMEDIATE_REDIRECTORS_ONLY
  [Documentation]  Test save_intermediate_redirs={redirectors=true, non_redirectors=false}
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

SAVE_INTERMEDIATE_DISABLED
  [Documentation]  Test save_intermediate_redirs with both options disabled
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

DEFAULT_TIMEOUT_VALUE
  [Documentation]  Test default timeout value (8s) from settings
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

CUSTOM_HTTP_TIMEOUT
  [Documentation]  Test custom http_timeout setting overrides default
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

CUSTOM_REDIS_TIMEOUT
  [Documentation]  Test custom redis_timeout setting
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

REDIRECTOR_SYMBOL_DISABLED
  [Documentation]  Test behavior when redirector_symbol is not configured
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

*** Keywords ***
Urlredirector Config Setup
  Run Dummy Http
  Rspamd Redis Setup

Urlredirector Config Teardown
  Rspamd Redis Teardown
  Dummy Http Teardown
  Terminate All Processes    kill=True
