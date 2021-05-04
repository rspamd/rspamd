*** Settings ***
Suite Setup     ARC Setup
Suite Teardown  Simple Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}        ${TESTDIR}/configs/arc.conf
${RSPAMD_SCOPE}  Suite
${URL_TLD}       ${TESTDIR}/../../contrib/publicsuffix/effective_tld_names.dat

*** Test Cases ***
ARC ALLOW CHECK
  Scan File  ${TESTDIR}/messages/arcallow.eml
  Expect Symbol  ARC_ALLOW

ARC BAD CHECK
  Scan File  ${TESTDIR}/messages/arcbad.eml
  Expect Symbol  ARC_INVALID


*** Keywords ***
ARC Setup
  New Setup  URL_TLD=${URL_TLD}
