*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py
Library         String

*** Variables ***
${SETTINGS_ARC}  {symbols_enabled = [ARC_CALLBACK]}

*** Test Cases ***
ARC ALLOW CHECK
  Scan File  ${RSPAMD_TESTDIR}/messages/arcallow.eml
  ...  Settings=${SETTINGS_ARC}
  Expect Symbol  ARC_ALLOW

ARC BAD CHECK
  Scan File  ${RSPAMD_TESTDIR}/messages/arcbad.eml
  ...  Settings=${SETTINGS_ARC}
  Expect Symbol  ARC_INVALID

ARC UNSEALED EXTRA AAR CHECK
  ${message} =  Get File  ${RSPAMD_TESTDIR}/messages/arcallow.eml
  ${file} =  Set Variable  ${RSPAMD_TMPDIR}/arc_extra_aar.eml
  Create File  ${file}  ARC-Authentication-Results: i=1; mx.microsoft.com 1; dmarc=pass header.from=forged.example\n${message}
  Scan File  ${file}
  ...  Settings=${SETTINGS_ARC}
  Expect Symbol  ARC_INVALID
  Do Not Expect Symbol  ARC_ALLOW
  Remove File  ${file}

ARC UNRESOLVABLE SEAL DOMAIN CHECK
  ${message} =  Get File  ${RSPAMD_TESTDIR}/messages/arcallow.eml
  ${message} =  Replace String  ${message}  d=microsoft.com; cv=none  d=micro!soft.com; cv=none
  Should Contain  ${message}  d=micro!soft.com; cv=none
  ${file} =  Set Variable  ${RSPAMD_TMPDIR}/arc_bad_seal_domain.eml
  Create File  ${file}  ${message}
  Scan File  ${file}
  ...  Settings=${SETTINGS_ARC}
  Expect Symbol  ARC_REJECT
  Do Not Expect Symbol  ARC_ALLOW
  Remove File  ${file}
