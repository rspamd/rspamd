*** Settings ***
Suite Setup     Generic Setup
Suite Teardown  Generic Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/maps.conf
${MESSAGE}      ${TESTDIR}/messages/spam_message.eml
${RSPAMD_SCOPE}  Suite

*** Test Cases ***
MAP - DNSBL HIT
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -i  127.0.0.2
  Check Rspamc  ${result}  DNSBL_MAP

MAP - DNSBL MISS
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -i  127.0.0.1
  Check Rspamc  ${result}  DNSBL_MAP  inverse=1  rc_nocheck=1