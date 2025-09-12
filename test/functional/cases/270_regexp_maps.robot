*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/regexp_maps.conf
${MESSAGE1}        ${RSPAMD_TESTDIR}/messages/advance_fee_fraud.eml
${MESSAGE2}        ${RSPAMD_TESTDIR}/messages/sa_header_body_raw.eml
${FULLMSG}         ${RSPAMD_TESTDIR}/messages/sa_full_boundary.eml
${URL1}            ${RSPAMD_TESTDIR}/messages/url1.eml
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
Advance Fee Fraud Detection
    [Documentation]    Test that advance fee fraud rules match correctly
    Scan File  ${MESSAGE1}
    Expect Symbol  ADVANCE_FEE_2
    Expect Symbol  ADVANCE_FEE_3
    # Verify filtered options (no __ atoms, max 5 options)
    ${symbols} =  Get From Dictionary  ${SCAN_RESULT}[symbols]  ADVANCE_FEE_2
    ${options} =  Get From Dictionary  ${symbols}  options
    ${options_count} =  Get Length  ${options}
    Should Be True  ${options_count} <= 5  msg=Too many options: ${options_count}
    FOR  ${option}  IN  @{options}
        Should Not Match Regexp  ${option}  ^__  msg=Option should not start with __: ${option}
    END

Meta Rule Combination
    [Documentation]    Test that meta rules correctly combine atom results
    Scan File  ${MESSAGE1}
    Expect Symbol With Score  ADVANCE_FEE_2  4.0
    Expect Symbol With Score  ADVANCE_FEE_3  5.0

No False Positives on Ham
    [Documentation]    Test that regexp rules don't trigger on legitimate messages
    Scan File  ${MESSAGE2}
    Do Not Expect Symbol  ADVANCE_FEE_2
    Do Not Expect Symbol  ADVANCE_FEE_3

Atom Rules Availability
    [Documentation]    Test that individual atom rules are available for combination
    Scan File  ${MESSAGE1}
    # These should be available internally but not shown as main results
    # We test by ensuring the meta rules work correctly
    Expect Symbol  ADVANCE_FEE_2
    Expect Symbol  ADVANCE_FEE_3

SA-Like: Header Atom
    [Documentation]    Header regexp atom works (SA_HDR_SUBJ)
    Scan File  ${MESSAGE2}
    Expect Symbol  SA_HDR_SUBJ

SA-Like: Body Atom
    [Documentation]    Body regexp atom works (SA_BODY_SIMPLE)
    Scan File  ${MESSAGE2}
    Expect Symbol  SA_BODY_SIMPLE

SA-Like: Rawbody Atom
    [Documentation]    Rawbody regexp atom works (SA_RAW_SIMPLE)
    Scan File  ${MESSAGE2}
    Expect Symbol  SA_RAW_SIMPLE

SA-Like: URI Atom
    [Documentation]    URI regexp atom works (SA_URI_SHORT)
    Scan File  ${URL1}
    Expect Symbol  SA_URI_SHORT

SA-Like: Full Atom
    [Documentation]    Full message regexp atom works (SA_FULL_BOUNDARY)
    Scan File  ${FULLMSG}
    Expect Symbol  SA_FULL_BOUNDARY

SA-Like: Selector From Domain
    [Documentation]    Selector-based atom (from:domain) works (SA_SEL_FROM_DOM)
    Scan File  ${MESSAGE2}
    Expect Symbol  SA_SEL_FROM_DOM

SA-Like: Selector URL TLD
    [Documentation]    Selector-based atom (specific_urls:tld) works (SA_SEL_URL_TLD)
    Scan File  ${URL1}
    Expect Symbol  SA_SEL_URL_TLD

SA-Like: Selector Negation
    [Documentation]    Selector negation works (SA_SEL_NOT_CORP)
    Scan File  ${MESSAGE2}
    Expect Symbol  SA_SEL_NOT_CORP

SA-Like: Meta AND
    [Documentation]    Meta rule with AND over header+body+selector
    Scan File  ${MESSAGE2}
    Expect Symbol  SA_META_AND

SA-Like: Meta OR
    [Documentation]    Meta rule with OR over uri+selector
    Scan File  ${URL1}
    Expect Symbol  SA_META_OR

SA-Like: Meta Complex
    [Documentation]    Complex meta combining negation and rawbody
    Scan File  ${MESSAGE2}
    Expect Symbol  SA_META_COMPLEX
