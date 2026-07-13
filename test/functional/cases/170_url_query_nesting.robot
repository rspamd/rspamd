*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/url_query_nesting.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/url_query_nesting.eml
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
DEEPLY NESTED QUERY URLS DO NOT CRASH THE WORKER
  [Documentation]  A URL whose query embeds another URL, repeated many times,
  ...              makes the URL multipattern scan re-enter itself once per
  ...              nesting level. The per-multipattern hyperscan scratch stack
  ...              must absorb that reentrancy (bounded by
  ...              RSPAMD_URL_QUERY_MAX_NESTING) instead of aborting the worker
  ...              on a "scr != NULL" assertion. Regression for the scratch-pool
  ...              exhaustion crash in rspamd_multipattern_lookup.
  Scan File  ${MESSAGE}
  # The scan completing at all proves the worker survived (a crash would make
  # Scan File fail). The outermost URL is always extracted; deeper hops are
  # followed up to the nesting cap.
  Expect URL  h0.example.org
  Expect URL  h1.example.org
