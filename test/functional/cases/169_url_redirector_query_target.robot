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
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/redir_query_target.eml
${REDIS_SCOPE}     Suite
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${SETTINGS}        {symbols_enabled=[URL_REDIRECTOR_CHECK]}

*** Test Cases ***
RESOLVE ENCODED QUERY TARGET THROUGH PATH-LESS WRAPPER
  # /combo_entry redirects to a PATH-LESS wrapper that carries the real target
  # percent-encoded (with its own &-separated params) in ?u=. Resolving the
  # full destination requires the request to a path-less URL to keep its query
  # and to send it percent-encoded; otherwise the wrapper sees a dropped or
  # &-truncated u and the target is lost.
  Scan File  ${MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://dest.com/?a=1&b=2
  # The followed wrapper also carried &other=...; a hop already resolved to a
  # real redirect target must not have its query re-extracted, so the extra
  # URL must not surface.
  Do Not Expect Extended URL  http://other.com/

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
