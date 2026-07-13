*** Settings ***
Suite Setup     Mx Check Setup
Suite Teardown  Mx Check Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/mx_check.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/spam_message.eml
${REDIS_SCOPE}     Suite
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${SETTINGS}        {symbols_enabled = [MX_INVALID]}

*** Test Cases ***
Null MX domain emits MX_NULL
  Scan File  ${MESSAGE}  From=test@nullmx.test  Settings=${SETTINGS}
  Expect Symbol  MX_NULL

NXDOMAIN domain emits MX_NONE
  Scan File  ${MESSAGE}  From=test@nxdmx.test  Settings=${SETTINGS}
  Expect Symbol  MX_NONE

Broken MX target emits MX_BROKEN
  Scan File  ${MESSAGE}  From=test@brokenmx.test  Settings=${SETTINGS}
  Expect Symbol  MX_BROKEN

Refused MX target emits MX_REFUSED
  Scan File  ${MESSAGE}  From=test@refused.test  Settings=${SETTINGS}
  Expect Symbol  MX_REFUSED

A-fallback (no MX, A points at closed port) emits MX_A_REFUSED
  Scan File  ${MESSAGE}  From=test@amxmiss.test  Settings=${SETTINGS}
  Expect Symbol  MX_A_REFUSED

Domain with no MX and no A (NODATA) emits MX_NONE
  Scan File  ${MESSAGE}  From=test@noaddr.test  Settings=${SETTINGS}
  Expect Symbol  MX_NONE

MX resolving only to private addresses emits MX_LOCAL_ONLY
  Scan File  ${MESSAGE}  From=test@localmx.test  Settings=${SETTINGS}
  Expect Symbol  MX_LOCAL_ONLY

MX resolving only to non-routable addresses emits MX_BOGON_ONLY
  Scan File  ${MESSAGE}  From=test@bogonmx.test  Settings=${SETTINGS}
  Expect Symbol  MX_BOGON_ONLY

MX hostname in exclude_mxs short-circuits with MX_WHITE
  Scan File  ${MESSAGE}  From=test@trustedmx.test  Settings=${SETTINGS}
  Expect Symbol  MX_WHITE
  Do Not Expect Symbol  MX_INVALID

MX whose only IP is in exclude_ips emits MX_SKIP
  Scan File  ${MESSAGE}  From=test@skipmx.test  Settings=${SETTINGS}
  Expect Symbol  MX_SKIP
  Do Not Expect Symbol  MX_INVALID

MX hostname in bad_mxs short-circuits with MX_BAD
  Scan File  ${MESSAGE}  From=test@badmx.test  Settings=${SETTINGS}
  Expect Symbol  MX_BAD
  Do Not Expect Symbol  MX_INVALID

MX whose IP is in bad_ips short-circuits with MX_IP_BAD
  Scan File  ${MESSAGE}  From=test@badipmx.test  Settings=${SETTINGS}
  Expect Symbol  MX_IP_BAD
  Do Not Expect Symbol  MX_INVALID

Local-network sender is skipped unless check_local is set
  Scan File  ${MESSAGE}  From=test@nxdmx.test  IP=127.0.0.1  Settings=${SETTINGS}
  Do Not Expect Symbol  MX_NONE
  Do Not Expect Symbol  MX_INVALID

*** Keywords ***
Mx Check Setup
  Rspamd Redis Setup

Mx Check Teardown
  Rspamd Redis Teardown
