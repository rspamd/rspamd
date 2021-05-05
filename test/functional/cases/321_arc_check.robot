*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/arc.conf
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../../contrib/publicsuffix/effective_tld_names.dat

*** Test Cases ***
ARC ALLOW CHECK
  Scan File  ${RSPAMD_TESTDIR}/messages/arcallow.eml
  Expect Symbol  ARC_ALLOW

ARC BAD CHECK
  Scan File  ${RSPAMD_TESTDIR}/messages/arcbad.eml
  Expect Symbol  ARC_INVALID

