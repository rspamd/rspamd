*** Settings ***
Suite Setup     Multimap Setup
Suite Teardown  Multimap Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/plugins.conf
${MESSAGE}      ${TESTDIR}/messages/spam_message.eml
${UTF_MESSAGE}  ${TESTDIR}/messages/utf.eml
${REDIS_SCOPE}  Suite
${RSPAMD_SCOPE}  Suite

*** Test Cases ***
MAP - DNSBL HIT
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -i  127.0.0.2
  Check Rspamc  ${result}  DNSBL_MAP

MAP - DNSBL MISS
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -i  127.0.0.1
  Check Rspamc  ${result}  DNSBL_MAP  inverse=1

MAP - IP HIT
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -i  127.0.0.1
  Check Rspamc  ${result}  IP_MAP

MAP - IP MISS
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -i  127.0.0.2
  Check Rspamc  ${result}  IP_MAP  inverse=1

MAP - IP MASK
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -i  10.1.0.10
  Check Rspamc  ${result}  IP_MAP

MAP - IP MASK MISS
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -i  11.1.0.10
  Check Rspamc  ${result}  IP_MAP  inverse=1

MAP - IP V6
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -i  ::1
  Check Rspamc  ${result}  IP_MAP

MAP - IP V6 MISS
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -i  fe80::1
  Check Rspamc  ${result}  IP_MAP  inverse=1

MAP - FROM
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --from  user@example.com
  Check Rspamc  ${result}  FROM_MAP

MAP - FROM MISS
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --from  user@other.com
  Check Rspamc  ${result}  FROM_MAP  inverse=1

MAP - FROM REGEXP
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --from  user123@test.com
  Check Rspamc  ${result}  REGEXP_MAP
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --from  somebody@exAmplE.com
  Check Rspamc  ${result}  REGEXP_MAP

MAP - FROM REGEXP MISS
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --from  user@other.org
  Check Rspamc  ${result}  REGEXP_MAP  inverse=1

MAP - DEPENDS HIT
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -i  147.243.1.47  --from  user123@microsoft.com
  Check Rspamc  ${result}  DEPS_MAP

MAP - DEPENDS MISS
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -i  127.0.0.1  --from  user123@microsoft.com
  Check Rspamc  ${result}  DEPS_MAP  inverse=1

MAP - MULSYM PLAIN
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --rcpt  user1@example.com
  Check Rspamc  ${result}  RCPT_MAP

MAP - MULSYM SCORE
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --rcpt  user2@example.com
  Check Rspamc  ${result}  RCPT_MAP (10.0

MAP - MULSYM SYMBOL
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --rcpt  user3@example.com
  Check Rspamc  ${result}  SYM1 (1.0

MAP - MULSYM SYMBOL MISS
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --rcpt  user4@example.com
  Check Rspamc  ${result}  RCPT_MAP (1.0

MAP - MULSYM SYMBOL + SCORE
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --rcpt  user5@example.com
  Check Rspamc  ${result}  SYM1 (-10.0

MAP - UTF
  ${result} =  Scan Message With Rspamc  ${UTF_MESSAGE}
  Check Rspamc  ${result}  HEADER_MAP

MAP - UTF MISS
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  HEADER_MAP  inverse=1

MAP - HOSTNAME
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --ip  127.0.0.1  --hostname  example.com
  Check Rspamc  ${result}  HOSTNAME_MAP

MAP - HOSTNAME MISS
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --ip  127.0.0.1  --hostname  rspamd.com
  Check Rspamc  ${result}  HOSTNAME_MAP  inverse=1

MAP - CDB - HOSTNAME
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --ip  127.0.0.1  --hostname  example.com
  Check Rspamc  ${result}  CDB_HOSTNAME

MAP - CDB - HOSTNAME MISS
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --ip  127.0.0.1  --hostname  rspamd.com
  Check Rspamc  ${result}  CDB_HOSTNAME  inverse=1

MAP - REDIS - HOSTNAME
  Redis HSET  hostname  redistest.example.net  ${EMPTY}
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --ip  127.0.0.1  --hostname  redistest.example.net
  Check Rspamc  ${result}  REDIS_HOSTNAME

MAP - REDIS - HOSTNAME MISS
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --ip  127.0.0.1  --hostname  rspamd.com
  Check Rspamc  ${result}  REDIS_HOSTNAME  inverse=1

MAP - REDIS - IP
  Redis HSET  ipaddr  127.0.0.1  ${EMPTY}
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --ip  127.0.0.1
  Check Rspamc  ${result}  REDIS_IPADDR

MAP - REDIS - IP - MISS
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --ip  8.8.8.8
  Check Rspamc  ${result}  REDIS_IPADDR  inverse=1

MAP - REDIS - FROM
  Redis HSET  emailaddr  from@rspamd.tk  ${EMPTY}
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --from  from@rspamd.tk
  Check Rspamc  ${result}  REDIS_FROMADDR

MAP - REDIS - FROM MISS
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --from  user@other.com
  Check Rspamc  ${result}  REDIS_FROMADDR  inverse=1

*** Keywords ***
Multimap Setup
  ${PLUGIN_CONFIG} =  Get File  ${TESTDIR}/configs/multimap.conf
  Set Suite Variable  ${PLUGIN_CONFIG}
  Generic Setup  PLUGIN_CONFIG
  Run Redis

Multimap Teardown
  Shutdown Process With Children  ${REDIS_PID}
  Generic Teardown
