*** Settings ***
Suite Setup     Urlredirector Setup
Suite Teardown  Urlredirector Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Test Tags       notparallel
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}               ${RSPAMD_TESTDIR}/configs/url_redirector.conf
${TEL_MESSAGE}          ${RSPAMD_TESTDIR}/messages/redir_tel_url.eml
${CHAIN_TEL_MESSAGE}    ${RSPAMD_TESTDIR}/messages/redir_chain_tel_url.eml
${MULTI_NON_HTTP_MESSAGE}    ${RSPAMD_TESTDIR}/messages/redir_multi_non_http.eml
${REDIS_SCOPE}          Suite
${RSPAMD_SCOPE}         Suite
${RSPAMD_URL_TLD}       ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${SETTINGS}             {symbols_enabled=[URL_REDIRECTOR_CHECK]}

*** Test Cases ***
SKIP NON-HTTP SCHEME REDIRECT
  # Test that url_redirector skips non-HTTP(S) schemes like tel:
  # The dummy HTTP server redirects /tel_redirect to tel:88006007775
  # url_redirector should follow the first redirect to 127.0.0.1:18080/tel_redirect
  # but then stop when it encounters the tel: scheme and not attempt HTTP request
  Scan File  ${TEL_MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  # The original URL should be processed
  Expect Extended URL  http://127.0.0.1:18080/tel_redirect
  Expect Symbol With Exact Options  URL_REDIRECTOR_NON_HTTP  telephone=127.0.0.1->tel:88006007775
  Do Not Expect Added URL  tel:88006007775

SKIP NON-HTTP SCHEME REDIRECT WITH INTERMEDIATE HOPS
  # Test that url_redirector traverses intermediate HTTP hops and still detects the
  # non-HTTP(S) terminal. chain_intermediate_1 -> chain_intermediate_2 -> tel:88006007776.
  # Intermediate redirector hops are not saved to chain by default (redirectors=false),
  # so the chain string only shows the original redirector host and the tel: target.
  Scan File  ${CHAIN_TEL_MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/chain_intermediate_1
  Expect Symbol With Exact Options  URL_REDIRECTOR_NON_HTTP  telephone=127.0.0.1->tel:88006007776
  Do Not Expect Added URL  tel:88006007776

MULTIPLE NON-HTTP REDIRECT TARGETS
  # Test that a single message with several redirector URLs each pointing to a different
  # non-HTTP scheme accumulates all scheme options in URL_REDIRECTOR_NON_HTTP.
  # tel_redirect -> tel:88006007775 (rspamd scheme: telephone)
  # mailto_redirect -> mailto:user@example.net (rspamd scheme: mailto)
  Scan File  ${MULTI_NON_HTTP_MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://127.0.0.1:18080/tel_redirect
  Expect Extended URL  http://127.0.0.1:18080/mailto_redirect
  Expect Symbol With Exact Options  URL_REDIRECTOR_NON_HTTP
  ...  telephone=127.0.0.1->tel:88006007775
  ...  mailto=127.0.0.1->mailto:user@example.net
  Do Not Expect Added URL  tel:88006007775
  Do Not Expect Added URL  mailto:user@example.net

*** Keywords ***
Urlredirector Setup
  Run Dummy Http
  Rspamd Redis Setup

Urlredirector Teardown
  Rspamd Redis Teardown
  Dummy Http Teardown
  Terminate All Processes    kill=True

Do Not Expect Added URL
  [Arguments]  ${url}
  ${found_url} =  Set Variable  ${FALSE}
  ${url_list} =  Convert To List  ${SCAN_RESULT}[urls]
  FOR  ${item}  IN  @{url_list}
    ${d} =  Convert To Dictionary  ${item}
    ${found_url} =  Evaluate  "${d}[url]" == "${url}"
    Exit For Loop If  ${found_url} == ${TRUE}
  END
  Should Be True  not ${found_url}  msg="URL ${url} should NOT be found but it was"
