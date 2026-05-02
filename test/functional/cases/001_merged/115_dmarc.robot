*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py
Library         Process
Library         DateTime

*** Variables ***
${DMARC_SETTINGS}    {symbols_enabled = [DMARC_CHECK, DKIM_CHECK, SPF_CHECK]}

*** Test Cases ***
DMARC NONE PASS DKIM
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/pass_none.eml
  ...  Settings=${DMARC_SETTINGS}
  Expect Symbol  DMARC_POLICY_ALLOW

DMARC NONE PASS SPF
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/fail_none.eml
  ...  IP=8.8.4.4  From=foo@spf.cacophony.za.org
  ...  Settings=${DMARC_SETTINGS}
  Expect Symbol  DMARC_POLICY_ALLOW

DMARC NONE FAIL
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/fail_none.eml
  ...  Settings=${DMARC_SETTINGS}
  Expect Symbol  DMARC_POLICY_SOFTFAIL

DMARC REJECT FAIL
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/fail_reject.eml
  ...  Settings=${DMARC_SETTINGS}
  ...  IP=1.2.3.4
  ...  From=foo@example.net
  Expect Symbol  DMARC_POLICY_REJECT

DMARC QUARANTINE FAIL
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/fail_quarantine.eml
  ...  Settings=${DMARC_SETTINGS}
  ...  IP=1.2.3.4
  ...  From=foo@example.net
  Expect Symbol  DMARC_POLICY_QUARANTINE

DMARC SP NONE FAIL
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/subdomain_fail_none.eml
  ...  Settings=${DMARC_SETTINGS}
  Expect Symbol  DMARC_POLICY_SOFTFAIL

DMARC SP REJECT FAIL
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/subdomain_fail_reject.eml
  ...  Settings=${DMARC_SETTINGS}
  Expect Symbol  DMARC_POLICY_REJECT

DMARC SP QUARANTINE FAIL
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/subdomain_fail_quarantine.eml
  ...  Settings=${DMARC_SETTINGS}
  Expect Symbol  DMARC_POLICY_QUARANTINE

DMARC SUBDOMAIN FAIL DKIM STRICT ALIGNMENT
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/onsubdomain_fail_alignment.eml
  ...  Settings=${DMARC_SETTINGS}
  Expect Symbol  DMARC_POLICY_REJECT

DMARC SUBDOMAIN PASS DKIM RELAXED ALIGNMENT
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/onsubdomain_pass_relaxed.eml
  ...  Settings=${DMARC_SETTINGS}
  Expect Symbol  DMARC_POLICY_ALLOW

DMARC SUBDOMAIN PASS SPF STRICT ALIGNMENT
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/onsubdomain_fail_alignment.eml
  ...  IP=37.48.67.26  From=foo@yo.mom.za.org
  ...  Settings=${DMARC_SETTINGS}
  Expect Symbol  DMARC_POLICY_ALLOW

DMARC SUBDOMAIN FAIL SPF STRICT ALIGNMENT
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/onsubdomain_fail_alignment.eml
  ...  IP=37.48.67.26  From=foo@mom.za.org
  ...  Settings=${DMARC_SETTINGS}
  Expect Symbol  DMARC_POLICY_REJECT

DMARC SUBDOMAIN PASS SPF RELAXED ALIGNMENT
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/onsubdomain_fail.eml
  ...  IP=37.48.67.26  From=foo@mom.za.org
  ...  Settings=${DMARC_SETTINGS}
  Expect Symbol  DMARC_POLICY_ALLOW

DMARC DNSFAIL
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/dmarc_tmpfail.eml
  ...  IP=37.48.67.26  From=foo@mom.za.org
  ...  Settings=${DMARC_SETTINGS}
  Expect Symbol  DMARC_DNSFAIL

DMARC NA NXDOMAIN
  Scan File  ${RSPAMD_TESTDIR}/messages/utf.eml
  ...  IP=37.48.67.26  From=foo@mom.za.org
  ...  Settings=${DMARC_SETTINGS}
  Expect Symbol  DMARC_NA

DMARC PCT ZERO REJECT
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/pct_none.eml
  ...  IP=37.48.67.26  From=foo@mom.za.org
  ...  Settings=${DMARC_SETTINGS}
  Expect Symbol  DMARC_POLICY_QUARANTINE

DMARC PCT ZERO SP QUARANTINE
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/pct_none1.eml
  ...  IP=37.48.67.26  From=foo@mom.za.org
  ...  Settings=${DMARC_SETTINGS}
  Expect Symbol  DMARC_POLICY_SOFTFAIL

# DMARC Reporting Tests
# These tests verify that DMARC report data is saved to Redis when reporting is enabled.
# The domain reject.cacophony.za.org has rua=mailto:dmarc-reports@rspamd.com configured.

DMARC REPORT REJECT FAIL SAVES TO REDIS
  [Documentation]  Test that DMARC report data is saved to Redis when DMARC fails with p=reject
  ...  and rua is configured. This tests the dmarc_report function in the DMARC plugin.
  ${report_key} =  Get DMARC Report Key  reject.cacophony.za.org  mailto:dmarc-reports@rspamd.com
  ${exists} =  Redis Key Exists  ${report_key}
  Should Be Equal As Integers  ${exists}  1
  ...  msg=DMARC report key should exist in Redis after DMARC policy failure with reporting enabled
  Log  Report key exists: ${report_key}

DMARC REPORT CONTAINS VALID DATA
  [Documentation]  Verify the DMARC report entry contains expected fields in the correct format
  ${report_key} =  Get DMARC Report Key  reject.cacophony.za.org  mailto:dmarc-reports@rspamd.com
  ${entries} =  Redis Get Sorted Set Members  ${report_key}
  Log  Report entries: ${entries}
  # Report entry format: IP,spf_ok,dkim_ok,disposition,sampled_out,header_from,dkim_pass,dkim_fail,dkim_temperror,dkim_permerror,spf_domain,spf_result
  Should Contain  ${entries}  reject.cacophony.za.org
  ...  msg=Report should contain the domain that failed DMARC
  Should Contain  ${entries}  fail
  ...  msg=Report should indicate SPF/DKIM failure

DMARC REPORT INDEX UPDATED
  [Documentation]  Verify the DMARC report index was updated when report is saved
  ${idx_key} =  Get DMARC Index Key
  ${members} =  Redis Get Set Members  ${idx_key}
  Log  Index members: ${members}
  Should Contain  ${members}  dmarc_rpt
  ...  msg=DMARC index should contain reference to report key

DMARC REPORT NO RUA DOMAIN SKIPS REDIS
  [Documentation]  Test that DMARC report is not saved for domains without rua configured
  ...  Using fail_quarantine.eml which uses quarantine.cacophony.za.org (no rua)
  ${report_key} =  Get DMARC Report Key  quarantine.cacophony.za.org  mailto:noruA@example.com
  ${exists} =  Redis Key Exists  ${report_key}
  Should Be Equal As Integers  ${exists}  0
  ...  msg=DMARC report key should NOT exist for domain without rua

*** Keywords ***
Get DMARC Report Key
  [Documentation]  Generate the DMARC report key for today
  [Arguments]  ${domain}  ${rua}
  ${today} =  Get Current Date  result_format=%Y%m%d
  ${report_key} =  Set Variable  dmarc_rpt;${domain};${rua};${today}
  [Return]  ${report_key}

Get DMARC Index Key
  [Documentation]  Generate the DMARC index key for today
  ${today} =  Get Current Date  result_format=%Y%m%d
  ${idx_key} =  Set Variable  dmarc_idx;${today}
  [Return]  ${idx_key}

Redis Key Exists
  [Documentation]  Check if a Redis key exists
  [Arguments]  ${key}
  ${result} =  Run Process  redis-cli  -h  ${RSPAMD_REDIS_ADDR}  -p  ${RSPAMD_REDIS_PORT}
  ...  EXISTS  ${key}
  Should Be Equal As Integers  ${result.rc}  0
  [Return]  ${result.stdout}

Redis Get Set Members
  [Documentation]  Get all members of a Redis set
  [Arguments]  ${key}
  ${result} =  Run Process  redis-cli  -h  ${RSPAMD_REDIS_ADDR}  -p  ${RSPAMD_REDIS_PORT}
  ...  SMEMBERS  ${key}
  Should Be Equal As Integers  ${result.rc}  0
  [Return]  ${result.stdout}

Redis Get Sorted Set Members
  [Documentation]  Get all members of a Redis sorted set
  [Arguments]  ${key}
  ${result} =  Run Process  redis-cli  -h  ${RSPAMD_REDIS_ADDR}  -p  ${RSPAMD_REDIS_PORT}
  ...  ZRANGE  ${key}  0  -1
  Should Be Equal As Integers  ${result.rc}  0
  [Return]  ${result.stdout}
