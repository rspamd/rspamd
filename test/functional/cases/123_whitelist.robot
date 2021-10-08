*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}               ${RSPAMD_TESTDIR}/configs/whitelist.conf
${M_DKIM_RSPAMD_BAD}    ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim_rspamd.eml
${M_DKIM_RSPAMD_OK}     ${RSPAMD_TESTDIR}/messages/dmarc/good_dkim_rspamd.eml
${M_DMARC_BAD}          ${RSPAMD_TESTDIR}/messages/dmarc/fail_none.eml
${M_DMARC_OK}           ${RSPAMD_TESTDIR}/messages/dmarc/pass_none.eml
${M_NO_DKIM_VALID_SPF}  ${RSPAMD_TESTDIR}/messages/dmarc/no_dkim_valid_spf.eml
${RSPAMD_SCOPE}         Suite
${RSPAMD_URL_TLD}       ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${UTF_MESSAGE}          ${RSPAMD_TESTDIR}/messages/utf.eml

*** Test Cases ***
WHITELISTS
  Scan File  ${M_DMARC_OK}  IP=8.8.4.4  From=foo@spf.cacophony.za.org
  Expect Symbol With Score  WHITELIST_DKIM  -1
  Expect Symbol With Score  STRICT_DMARC  -3
  Expect Symbol With Score  WHITELIST_SPF_DKIM  -3
  Expect Symbol With Score  WHITELIST_DDS  -3
  Expect Symbol With Score  WHITELIST_DMARC  -2
  Expect Symbol With Score  WHITELIST_DMARC_DKIM  -2
  Expect Symbol With Score  WHITELIST_SPF  -1
  Do Not Expect Symbol  BLACKLIST_SPF
  Do Not Expect Symbol  BLACKLIST_DKIM
  Do Not Expect Symbol  BLACKLIST_DMARC

BLACKLIST SHOULD FIRE IF ANY CONSTRAINT FAILED
  Scan File  ${M_DMARC_OK}  IP=9.8.4.4  From=foo@spf.cacophony.za.org
  Expect Symbol With Score  BLACKLIST_DDS  3
  Do Not Expect Symbol  WHITELIST_DDS
  Do Not Expect Symbol  WHITELIST_SPF

BLACKLISTS
  Scan File  ${M_DMARC_BAD}  IP=9.8.4.4  From=foo@cacophony.za.org
  Expect Symbol With Score  BLACKLIST_SPF  3
  Expect Symbol With Score  BLACKLIST_SPF  3
  Expect Symbol With Score  STRICT_DMARC  3
  Expect Symbol With Score  BLACKLIST_DDS  3
  Expect Symbol With Score  BLACKLIST_DMARC  2
  Do Not Expect Symbol  WHITELIST_DDS
  Do Not Expect Symbol  WHITELIST_SPF
  Do Not Expect Symbol  WHITELIST_DKIM
  Do Not Expect Symbol  WHITELIST_DMARC
  Do Not Expect Symbol  WHITELIST_DMARC_DKIM

WHITELIST_WL_ONLY - VALID SPF AND VALID DKIM
  Scan File  ${M_DKIM_RSPAMD_OK}
  ...  IP=88.99.142.95
  Expect Symbol With Score  WHITELIST_DKIM  -2
  Do Not Expect Symbol  BLACKLIST_DKIM
  Expect Symbol With Score  R_SPF_ALLOW  1
  Expect Symbol With Score  R_DKIM_ALLOW  1
  Expect Symbol With Score  WHITELIST_SPF_DKIM  -6

BLACKLISTS_WL_ONLY - VALID SPF AND INVALID DKIM
  Scan File  ${M_DKIM_RSPAMD_BAD}
  ...  IP=88.99.142.95
  Expect Symbol With Score  R_DKIM_REJECT  1
  Do Not Expect Symbol  WHITELIST_DKIM
  Do Not Expect Symbol  BLACKLIST_DKIM
  Expect Symbol With Score  R_SPF_ALLOW  1
  Expect Symbol With Score  R_DKIM_REJECT  1
  Do Not Expect Symbol  WHITELIST_SPF_DKIM
  Do Not Expect Symbol  R_DKIM_ALLOW

VALID SPF and NO DKIM
  Scan File  ${M_NO_DKIM_VALID_SPF}
  ...  IP=88.99.142.95
  Expect Symbol With Score  R_SPF_ALLOW  1
  Expect Symbol With Score  R_DKIM_NA  1
  Do Not Expect Symbol  R_DKIM_REJECT
  Do Not Expect Symbol  WHITELIST_SPF_DKIM
  Do Not Expect Symbol  R_DKIM_ALLOW
