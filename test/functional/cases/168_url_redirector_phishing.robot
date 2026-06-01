*** Settings ***
Suite Setup     Urlredirector Setup
Suite Teardown  Urlredirector Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Test Tags       notparallel
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/url_redirector_phishing.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/redir_phishing_safe.eml
${REDIS_SCOPE}     Suite
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${SETTINGS}        {symbols_enabled=[URL_REDIRECTOR_CHECK, PHISHING]}

*** Test Cases ***
PHISHING NO FP WHEN DISPLAY TEXT EQUALS REDIRECT DEST
  # t.co (a known redirector, faked to the dummy HTTP server) resolves to the
  # same domain shown in the anchor text, so the resolved redirect destination
  # equals the displayed URL -- phishing must not fire.
  Scan File  ${MESSAGE}  Settings=${SETTINGS}
  Expect Symbol  URL_REDIRECTOR
  Do Not Expect Symbol  PHISHING

*** Keywords ***
Urlredirector Setup
  Run Dummy Http
  Rspamd Redis Setup
  ${MESSAGE} =  Render Message Template  ${MESSAGE}
  Set Suite Variable  ${MESSAGE}

Urlredirector Teardown
  Rspamd Redis Teardown
  Dummy Http Teardown
  Terminate All Processes    kill=True
