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
${URL1}         ${TESTDIR}/messages/url1.eml
${URL2}         ${TESTDIR}/messages/url2.eml
${URL3}         ${TESTDIR}/messages/url3.eml
${URL4}         ${TESTDIR}/messages/url4.eml
${URL5}         ${TESTDIR}/messages/url5.eml

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

MAP - REDIS - URL TLD - HIT
  Redis HSET  hostname  example.com  ${EMPTY}
  ${result} =  Scan Message With Rspamc  ${URL1}
  Check Rspamc  ${result}  REDIS_URL_TLD

MAP - REDIS - URL TLD - MISS
  ${result} =  Scan Message With Rspamc  ${URL2}
  Check Rspamc  ${result}  REDIS_URL_TLD  inverse=1

MAP - REDIS - URL RE FULL - HIT
  Redis HSET  fullurlre  html  ${EMPTY}
  ${result} =  Scan Message With Rspamc  ${URL2}
  Check Rspamc  ${result}  REDIS_URL_RE_FULL

MAP - REDIS - URL RE FULL - MISS
  ${result} =  Scan Message With Rspamc  ${URL1}
  Check Rspamc  ${result}  REDIS_URL_RE_FULL  inverse=1

MAP - REDIS - URL FULL - HIT
  Redis HSET  fullurl  https://www.example.com/foo?a=b  ${EMPTY}
  ${result} =  Scan Message With Rspamc  ${URL1}
  Check Rspamc  ${result}  REDIS_URL_FULL

MAP - REDIS - URL FULL - MISS
  ${result} =  Scan Message With Rspamc  ${URL2}
  Check Rspamc  ${result}  REDIS_URL_FULL  inverse=1

MAP - REDIS - URL PHISHED - HIT
  Redis HSET  phishedurl  www.rspamd.com  ${EMPTY}
  ${result} =  Scan Message With Rspamc  ${URL3}
  Check Rspamc  ${result}  REDIS_URL_PHISHED

MAP - REDIS - URL PHISHED - MISS
  ${result} =  Scan Message With Rspamc  ${URL4}
  Check Rspamc  ${result}  REDIS_URL_PHISHED  inverse=1

MAP - REDIS - URL PLAIN REGEX - HIT
  Redis HSET  urlre  www  ${EMPTY}
  ${result} =  Scan Message With Rspamc  ${URL3}
  Check Rspamc  ${result}  REDIS_URL_RE_PLAIN

MAP - REDIS - URL PLAIN REGEX - MISS
  ${result} =  Scan Message With Rspamc  ${URL4}
  Check Rspamc  ${result}  REDIS_URL_RE_PLAIN  inverse=1

MAP - REDIS - URL TLD REGEX - HIT
  Redis HSET  tldre  net  ${EMPTY}
  ${result} =  Scan Message With Rspamc  ${URL5}
  Check Rspamc  ${result}  REDIS_URL_RE_TLD

MAP - REDIS - URL TLD REGEX - MISS
  ${result} =  Scan Message With Rspamc  ${URL4}
  Check Rspamc  ${result}  REDIS_URL_RE_TLD  inverse=1

MAP - REDIS - URL NOFILTER - HIT
  Redis HSET  urlnofilter  www.example.net  ${EMPTY}
  ${result} =  Scan Message With Rspamc  ${URL5}
  Check Rspamc  ${result}  REDIS_URL_NOFILTER

MAP - REDIS - URL NOFILTER - MISS
  ${result} =  Scan Message With Rspamc  ${URL4}
  Check Rspamc  ${result}  REDIS_URL_NOFILTER  inverse=1

MAP - REDIS - ASN - HIT
  Redis HSET  asn  15169  ${EMPTY}
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -i  8.8.8.8
  Check Rspamc  ${result}  REDIS_ASN

MAP - REDIS - ASN - MISS
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -i  46.228.47.114
  Check Rspamc  ${result}  REDIS_ASN  inverse=1

MAP - REDIS - CC - HIT
  Redis HSET  cc  US  ${EMPTY}
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -i  8.8.8.8
  Check Rspamc  ${result}  REDIS_COUNTRY

MAP - REDIS - CC - MISS
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -i  46.228.47.114
  Check Rspamc  ${result}  REDIS_COUNTRY  inverse=1

MAP - REDIS - ASN FILTERED - HIT
  Redis HSET  asn  1  ${EMPTY}
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -i  8.8.8.8
  Check Rspamc  ${result}  REDIS_ASN_FILTERED

MAP - REDIS - ASN FILTERED - MISS
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -i  46.228.47.114
  Check Rspamc  ${result}  REDIS_ASN_FILTERED  inverse=1

*** Keywords ***
Multimap Setup
  ${PLUGIN_CONFIG} =  Get File  ${TESTDIR}/configs/multimap.conf
  Set Suite Variable  ${PLUGIN_CONFIG}
  Generic Setup  PLUGIN_CONFIG
  Run Redis

Multimap Teardown
  Shutdown Process With Children  ${REDIS_PID}
  Generic Teardown
