*** Settings ***
Suite Setup     Urlredirector Cache Setup
Suite Teardown  Urlredirector Cache Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/url_redirector_chain.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/redir.eml
${REDIS_SCOPE}     Suite
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${SETTINGS}        {symbols_enabled=[URL_REDIRECTOR_CHECK]}

*** Test Cases ***
CACHE HOP MARKERS
  [Documentation]  Test that cache entries have correct hop markers
  ...              - ^hop: for intermediate hops
  ...              - ^nested: for limit exceeded
  ...              - no marker for terminal URLs
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

PER-ADJACENT-PAIR CACHE LAYOUT
  [Documentation]  Test PR 6014 cache layout: one Redis entry per adjacent URL pair
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

CACHE WALK WITH MARKERS
  [Documentation]  Test cache walk behavior: reader follows markers until terminal
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

SELF-HEALING CACHE
  [Documentation]  Test self-healing: ^nested: marker upgrade on extension
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

CYCLE DETECTION
  [Documentation]  Test cycle protection with per-walk seen-set
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}

REDIS TIMEOUT APPLIED
  [Documentation]  Test that redis_timeout setting is applied to Redis calls
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

TOP_URLS TRACKING
  [Documentation]  Test that ZINCRBY on top_urls uses canonical URL string
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

RESERVATION LOCK
  [Documentation]  Test that reservation lock has correct TTL = settings.timeout
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/hello

*** Keywords ***
Urlredirector Cache Setup
  Run Dummy Http
  Rspamd Redis Setup

Urlredirector Cache Teardown
  Rspamd Redis Teardown
  Dummy Http Teardown
  Terminate All Processes    kill=True
