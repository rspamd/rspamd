*** Settings ***
Suite Setup     HTML Fuzzy Setup
Suite Teardown  Rspamd Redis Teardown
Resource        lib.robot

*** Variables ***
${HTML_TEMPLATE_1}         ${RSPAMD_TESTDIR}/messages/html_template_1.eml
${HTML_TEMPLATE_1_VAR}     ${RSPAMD_TESTDIR}/messages/html_template_1_variation.eml
${HTML_PHISHING}           ${RSPAMD_TESTDIR}/messages/html_phishing.eml
${FLAG_HTML_WHITE}         100
${FLAG_HTML_SPAM}          101

*** Keywords ***
HTML Fuzzy Setup
  Set Suite Variable  ${RSPAMD_FUZZY_ALGORITHM}  mumhash
  Set Suite Variable  ${RSPAMD_FUZZY_SERVER_MODE}  servers
  Set Suite Variable  ${SETTINGS_FUZZY_CHECK}  servers = "${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_FUZZY}"; html_shingles = true; min_html_tags = 5;
  Rspamd Redis Setup

HTML Fuzzy Add Whitelist
  [Documentation]  Learn legitimate HTML template
  ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  -w  10  -f  ${FLAG_HTML_WHITE}  fuzzy_add  ${HTML_TEMPLATE_1}
  Check Rspamc  ${result}
  Sync Fuzzy Storage

HTML Fuzzy Check Variation
  [Documentation]  Check variation of same template (different text, same structure)
  Scan File  ${HTML_TEMPLATE_1_VAR}
  Expect Symbol  R_TEST_FUZZY_DENIED
  ${symbols} =  Get Rspamd Symbols
  Log  Fuzzy symbols: ${symbols}

HTML Fuzzy Check Phishing
  [Documentation]  Check phishing email (same structure, different CTA domains)
  Scan File  ${HTML_PHISHING}
  # Should match structure but CTA differs
  # Depending on CTA weight, might have lower score or specific handling
  ${symbols} =  Get Rspamd Symbols
  Log  Phishing check symbols: ${symbols}

*** Test Cases ***
HTML Fuzzy Add Whitelist Test
  HTML Fuzzy Add Whitelist

HTML Fuzzy Variation Match Test
  HTML Fuzzy Check Variation

HTML Fuzzy Phishing Detection Test
  HTML Fuzzy Check Phishing
