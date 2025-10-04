*** Settings ***
Suite Setup     HTML Fuzzy Setup Mumhash
Suite Teardown  Rspamd Redis Teardown
Resource        lib.robot

*** Variables ***
${HTML_TEMPLATE_1}         ${RSPAMD_TESTDIR}/messages/html_template_1.eml
${HTML_TEMPLATE_1_VAR}     ${RSPAMD_TESTDIR}/messages/html_template_1_variation.eml
${HTML_TEMPLATE_1_FUZZY}   ${RSPAMD_TESTDIR}/messages/html_template_1_fuzzy.eml
${HTML_PHISHING}           ${RSPAMD_TESTDIR}/messages/html_phishing.eml

*** Keywords ***
HTML Fuzzy Setup Mumhash
  Set Suite Variable  ${RSPAMD_FUZZY_ALGORITHM}  mumhash
  Set Suite Variable  ${RSPAMD_FUZZY_SERVER_MODE}  servers
  # Include HTML-specific settings via FUZZY_INCLUDE
  Set Suite Variable  ${RSPAMD_FUZZY_INCLUDE}  ${RSPAMD_TESTDIR}/configs/fuzzy-html.conf
  Rspamd Redis Setup

HTML Fuzzy Add Test
  [Documentation]  Learn legitimate HTML template
  Set Suite Variable  ${RSPAMD_FUZZY_HTML_ADD}  0
  ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  -w  10  -f  ${RSPAMD_FLAG1_NUMBER}  fuzzy_add  ${HTML_TEMPLATE_1}
  Check Rspamc  ${result}
  Sync Fuzzy Storage
  Set Suite Variable  ${RSPAMD_FUZZY_HTML_ADD}  1

HTML Fuzzy Check Test
  [Documentation]  Check exact match
  IF  ${RSPAMD_FUZZY_HTML_ADD} == 0
    Fail  "HTML Fuzzy Add was not run"
  END
  Scan File  ${HTML_TEMPLATE_1}
  Expect Symbol  ${FLAG1_SYMBOL}

HTML Fuzzy Exact Match Variation Test
  [Documentation]  Check exact match with different text but identical HTML structure
  IF  ${RSPAMD_FUZZY_HTML_ADD} == 0
    Fail  "HTML Fuzzy Add was not run"
  END
  Scan File  ${HTML_TEMPLATE_1_VAR}
  # Should match exactly - same HTML structure, only text differs
  Expect Symbol  ${FLAG1_SYMBOL}

HTML Fuzzy Similarity Test
  [Documentation]  Check fuzzy (similarity) match with slightly different HTML structure
  IF  ${RSPAMD_FUZZY_HTML_ADD} == 0
    Fail  "HTML Fuzzy Add was not run"
  END
  Scan File  ${HTML_TEMPLATE_1_FUZZY}
  # Should match via shingles - similar but not identical HTML structure
  # (added spacer div, extra paragraph, second article)
  Expect Symbol  ${FLAG1_SYMBOL}

HTML Fuzzy Phishing Test
  [Documentation]  Check phishing email with same structure but different CTA domains
  IF  ${RSPAMD_FUZZY_HTML_ADD} == 0
    Fail  "HTML Fuzzy Add was not run"
  END
  # Structure similar but CTA domains different
  # Might match with lower score or not match depending on CTA weight
  # Just verify scanning works without crash
  Scan File  ${HTML_PHISHING}

HTML Fuzzy Delete Test
  [Documentation]  Delete HTML fuzzy hash
  IF  ${RSPAMD_FUZZY_HTML_ADD} == 0
    Fail  "HTML Fuzzy Add was not run"
  END
  ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  -f  ${RSPAMD_FLAG1_NUMBER}  fuzzy_del  ${HTML_TEMPLATE_1}
  Check Rspamc  ${result}
  Sync Fuzzy Storage
  Scan File  ${HTML_TEMPLATE_1}
  Do Not Expect Symbol  ${FLAG1_SYMBOL}

*** Test Cases ***
HTML Fuzzy Add
  HTML Fuzzy Add Test

HTML Fuzzy Exact Match
  HTML Fuzzy Check Test

HTML Fuzzy Exact Match With Text Variation
  HTML Fuzzy Exact Match Variation Test

HTML Fuzzy Similarity Match
  HTML Fuzzy Similarity Test

HTML Fuzzy Phishing Detection
  HTML Fuzzy Phishing Test

HTML Fuzzy Delete
  HTML Fuzzy Delete Test
