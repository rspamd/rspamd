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
  # MX_INVALID is the primary skip-mail signal for Null MX domains
  Expect Symbol  MX_INVALID

NXDOMAIN domain emits MX_NXDOMAIN
  Scan File  ${MESSAGE}  From=test@nxdmx.test  Settings=${SETTINGS}
  Expect Symbol  MX_NXDOMAIN
  Expect Symbol  MX_INVALID

Broken MX target emits MX_BROKEN
  Scan File  ${MESSAGE}  From=test@brokenmx.test  Settings=${SETTINGS}
  Expect Symbol  MX_BROKEN
  Expect Symbol  MX_INVALID

Refused MX target emits MX_REFUSED
  Scan File  ${MESSAGE}  From=test@refused.test  Settings=${SETTINGS}
  Expect Symbol  MX_REFUSED
  Expect Symbol  MX_INVALID

A-fallback (no MX, A points at closed port) emits MX_MISSING and MX_INVALID
  Scan File  ${MESSAGE}  From=test@amxmiss.test  Settings=${SETTINGS}
  Expect Symbol  MX_MISSING
  Expect Symbol  MX_INVALID

Domain with no MX and no A (NODATA) is not treated as NXDOMAIN
  Scan File  ${MESSAGE}  From=test@noaddr.test  Settings=${SETTINGS}
  Expect Symbol  MX_MISSING
  Expect Symbol  MX_INVALID
  Do Not Expect Symbol  MX_NXDOMAIN

MX resolving only to private addresses emits MX_LOCAL_ONLY
  Scan File  ${MESSAGE}  From=test@localmx.test  Settings=${SETTINGS}
  Expect Symbol  MX_LOCAL_ONLY
  Expect Symbol  MX_INVALID

MX resolving only to non-routable addresses emits MX_BOGON_ONLY
  Scan File  ${MESSAGE}  From=test@bogonmx.test  Settings=${SETTINGS}
  Expect Symbol  MX_BOGON_ONLY
  Expect Symbol  MX_INVALID

MX hostname in exclude_mxs short-circuits with MX_WHITE
  Scan File  ${MESSAGE}  From=test@trustedmx.test  Settings=${SETTINGS}
  Expect Symbol  MX_WHITE
  Do Not Expect Symbol  MX_INVALID

MX whose only IP is in exclude_ips emits MX_SKIP
  Scan File  ${MESSAGE}  From=test@skipmx.test  Settings=${SETTINGS}
  Expect Symbol  MX_SKIP
  Do Not Expect Symbol  MX_INVALID

Local-network sender is skipped unless check_local is set
  Scan File  ${MESSAGE}  From=test@nxdmx.test  IP=127.0.0.1  Settings=${SETTINGS}
  Do Not Expect Symbol  MX_NXDOMAIN
  Do Not Expect Symbol  MX_INVALID

*** Keywords ***
Mx Check Setup
  Rspamd Redis Setup

Mx Check Teardown
  Rspamd Redis Teardown
