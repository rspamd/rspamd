*** Settings ***
Test Setup      Rspamd Setup
Test Teardown   Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/regexp_maps.conf
${MESSAGE1}        ${RSPAMD_TESTDIR}/messages/advance_fee_fraud.eml
${MESSAGE2}        ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_SCOPE}    Test
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
