*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Library         ${RSPAMD_TESTDIR}/lib/multistage_users.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}             ${RSPAMD_TESTDIR}/configs/multistage_users.conf
${RSPAMD_LUA_SCRIPT}  ${RSPAMD_TESTDIR}/lua/multistage_users.lua
${RSPAMD_SCOPE}       Suite
${RSPAMD_URL_TLD}     ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${RSPAMD_DATA_RELAY_PLUGIN}  disabled

*** Test Cases ***
User And Recipient DATA Policies With Self Scan
  Multistage Users Policies  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}

User And Recipient DATA Policies With Remote Scanner
  Multistage Users Policies  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER_SSL}

ASN And Multimap Self Scan Parity
  Multistage Users Parity  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}

ASN And Multimap Remote Parity
  Multistage Users Parity  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER_SSL}

Only Audited Envelope Rules Export Reusable Results
  Multistage Users Record  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}

Invalid Producer Facts Rerun Before Inserting Results
  Multistage Users Invalid Facts  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}

ASN Distinguishes Missing Data From Lookup Failure
  Multistage Users ASN Outcomes  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}

Ordinary Settings Cannot Override DATA Policy
  Multistage Users Settings  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}

Ordinary Multimap Actions Run At EOM
  Multistage Users Action  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}
