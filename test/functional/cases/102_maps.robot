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

MAP - IP HIT
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -i  127.0.0.1
  Check Rspamc  ${result}  IP_MAP

MAP - IP MISS
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -i  127.0.0.2
  Check Rspamc  ${result}  IP_MAP  inverse=1  rc_nocheck=1

MAP - IP MASK
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -i  10.1.0.10
   Check Rspamc  ${result}  IP_MAP

MAP - IP MASK MISS
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -i  11.1.0.10
  Check Rspamc  ${result}  IP_MAP  inverse=1  rc_nocheck=1

MAP - IP V6
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -i  ::1
   Check Rspamc  ${result}  IP_MAP

MAP - IP V6 MISS
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -i  fe80::1
  Check Rspamc  ${result}  IP_MAP  inverse=1  rc_nocheck=1

MAP - FROM
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --from  user@example.com
   Check Rspamc  ${result}  FROM_MAP

MAP - FROM MISS
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --from  user@other.com
  Check Rspamc  ${result}  FROM_MAP  inverse=1  rc_nocheck=1

MAP - FROM REGEXP
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --from  user123@test.com
   Check Rspamc  ${result}  REGEXP_MAP
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --from  somebody@exAmplE.com
   Check Rspamc  ${result}  REGEXP_MAP

MAP - FROM REGEXP MISS
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --from  user@other.org
  Check Rspamc  ${result}  REGEXP_MAP  inverse=1  rc_nocheck=1