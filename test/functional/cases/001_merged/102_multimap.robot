*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${FREEMAIL_CC}     ${RSPAMD_TESTDIR}/messages/freemailcc.eml
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RCVD1}           ${RSPAMD_TESTDIR}/messages/received1.eml
${RCVD2}           ${RSPAMD_TESTDIR}/messages/received2.eml
${RCVD3}           ${RSPAMD_TESTDIR}/messages/received3.eml
${RCVD4}           ${RSPAMD_TESTDIR}/messages/received4.eml
${URL1}            ${RSPAMD_TESTDIR}/messages/url1.eml
${URL2}            ${RSPAMD_TESTDIR}/messages/url2.eml
${URL3}            ${RSPAMD_TESTDIR}/messages/url3.eml
${URL4}            ${RSPAMD_TESTDIR}/messages/url4.eml
${URL5}            ${RSPAMD_TESTDIR}/messages/url5.eml
${URL_ICS}         ${RSPAMD_TESTDIR}/messages/ics.eml
${UTF_MESSAGE}     ${RSPAMD_TESTDIR}/messages/utf.eml

*** Test Cases ***
URL_ICS
  Scan File  ${URL_ICS}
  ...   Settings={symbols_enabled = []}
  Expect URL  test.com

MAP - DNSBL HIT
  Scan File  ${MESSAGE}  IP=127.0.0.2
  ...   Settings={symbols_enabled = [DNSBL_MAP]}
  Expect Symbol  DNSBL_MAP

MAP - DNSBL MISS
  Scan File  ${MESSAGE}  IP=127.0.0.1
  ...   Settings={symbols_enabled = [DNSBL_MAP]}
  Do Not Expect Symbol  DNSBL_MAP

MAP - IP HIT
  Scan File  ${MESSAGE}  IP=127.0.0.1
  ...   Settings={symbols_enabled = [IP_MAP]}
  Expect Symbol  IP_MAP

MAP - IP MISS
  Scan File  ${MESSAGE}  IP=127.0.0.2
  ...   Settings={symbols_enabled = [IP_MAP]}
  Do Not Expect Symbol  IP_MAP

MAP - IP MASK
  Scan File  ${MESSAGE}  IP=10.1.0.10
  ...   Settings={symbols_enabled = [IP_MAP]}
  Expect Symbol  IP_MAP

MAP - IP MASK MISS
  Scan File  ${MESSAGE}  IP=11.1.0.10
  ...   Settings={symbols_enabled = [IP_MAP]}
  Do Not Expect Symbol  IP_MAP

MAP - IP V6
  Scan File  ${MESSAGE}  IP=::1
  ...   Settings={symbols_enabled = [IP_MAP]}
  Expect Symbol  IP_MAP

MAP - IP V6 MISS
  Scan File  ${MESSAGE}  IP=fe80::1
  ...   Settings={symbols_enabled = [IP_MAP]}
  Do Not Expect Symbol  IP_MAP

MAP - FROM
  Scan File  ${MESSAGE}  From=user@example.com
  ...   Settings={symbols_enabled = [FROM_MAP]}
  Expect Symbol  FROM_MAP

MAP - COMBINED IP MASK FROM
  Scan File  ${MESSAGE}  IP=10.1.0.10  From=user@example.com
  ...   Settings={symbols_enabled = [COMBINED_MAP_AND, COMBINED_MAP_OR]}
  Expect Symbol With Score  COMBINED_MAP_AND  10
  Expect Symbol  COMBINED_MAP_OR

MAP - COMBINED IP MASK ONLY
  Scan File  ${MESSAGE}  IP=10.1.0.10
  ...   Settings={symbols_enabled = [COMBINED_MAP_AND, COMBINED_MAP_OR]}
  Do Not Expect Symbol  COMBINED_MAP_AND
  Expect Symbol  COMBINED_MAP_OR

MAP - COMBINED FROM ONLY
  Scan File  ${MESSAGE}  From=user@example.com
  ...   Settings={symbols_enabled = [COMBINED_MAP_AND, COMBINED_MAP_OR]}
  Do Not Expect Symbol  COMBINED_MAP_AND
  Expect Symbol  COMBINED_MAP_OR

MAP - COMBINED MISS
  Scan File  ${MESSAGE}  IP=11.1.0.10  From=user@other.com
  ...   Settings={symbols_enabled = [COMBINED_MAP_AND, COMBINED_MAP_OR]}
  Do Not Expect Symbol  COMBINED_MAP_AND
  Do Not Expect Symbol  COMBINED_MAP_OR

MAP - FROM MISS
  Scan File  ${MESSAGE}  From=user@other.com
  ...   Settings={symbols_enabled = [FROM_MAP]}
  Do Not Expect Symbol  FROM_MAP

MAP - FROM REGEXP
  Scan File  ${MESSAGE}  From=user123@test.com
  ...   Settings={symbols_enabled = [REGEXP_MAP]}
  Expect Symbol  REGEXP_MAP
  Scan File  ${MESSAGE}  From=somebody@example.com
  ...   Settings={symbols_enabled = [REGEXP_MAP]}
  Expect Symbol  REGEXP_MAP

MAP - FROM REGEXP MISS
  Scan File  ${MESSAGE}  From=user@other.org
  ...   Settings={symbols_enabled = [REGEXP_MAP]}
  Do Not Expect Symbol  REGEXP_MAP

MAP - RCPT DOMAIN HIT
  Scan File  ${MESSAGE}  Rcpt=user@example.com
  ...   Settings={symbols_enabled = [RCPT_DOMAIN]}
  Expect Symbol  RCPT_DOMAIN

MAP - RCPT DOMAIN MISS
  Scan File  ${MESSAGE}  Rcpt=example.com@user
  ...   Settings={symbols_enabled = [RCPT_DOMAIN]}
  Do Not Expect Symbol  RCPT_DOMAIN

MAP - RCPT USER HIT
  Scan File  ${MESSAGE}  Rcpt=bob@example.com
  ...   Settings={symbols_enabled = [RCPT_USER]}
  Expect Symbol  RCPT_USER

MAP - RCPT USER MISS
  Scan File  ${MESSAGE}  From=example.com@bob
  ...   Settings={symbols_enabled = [RCPT_USER]}
  Do Not Expect Symbol  RCPT_USER

MAP - DEPENDS HIT
  Scan File  ${MESSAGE}  IP=88.99.142.95  From=user123@rspamd.com
  ...   Settings={symbols_enabled = [DEPS_MAP,REGEXP_MAP,FROM_MAP,SPF_CHECK]}
  Expect Symbol  DEPS_MAP

MAP - DEPENDS MISS
  Scan File  ${MESSAGE}  IP=1.2.3.4  From=user123@rspamd.com
  ...   Settings={symbols_enabled = [DEPS_MAP,REGEXP_MAP,FROM_MAP,SPF_CHECK]}
  Do Not Expect Symbol  DEPS_MAP

MAP - MULSYM PLAIN
  Scan File  ${MESSAGE}  Rcpt=user1@example.com
  ...   Settings={symbols_enabled = [RCPT_MAP, SYM1]}
  Expect Symbol  RCPT_MAP

MAP - MULSYM SCORE
  Scan File  ${MESSAGE}  Rcpt=user2@example.com
  ...   Settings={symbols_enabled = [RCPT_MAP, SYM1]}
  Expect Symbol With Score  RCPT_MAP  10.0

MAP - MULSYM SYMBOL
  Scan File  ${MESSAGE}  Rcpt=user3@example.com
  ...   Settings={symbols_enabled = [RCPT_MAP, SYM1]}
  Expect Symbol With Score  SYM1  1.0

MAP - MULSYM SYMBOL MISS
  Scan File  ${MESSAGE}  Rcpt=user4@example.com
  ...   Settings={symbols_enabled = [RCPT_MAP, SYM1]}
  Expect Symbol With Score  RCPT_MAP  1.0

MAP - MULSYM SYMBOL + SCORE
  Scan File  ${MESSAGE}  Rcpt=user5@example.com
  ...   Settings={symbols_enabled = [RCPT_MAP, SYM1]}
  Expect Symbol With Score  SYM1  -10.1

MAP - UTF
  Scan File  ${UTF_MESSAGE}
  ...   Settings={symbols_enabled = [HEADER_MAP]}
  Expect Symbol  HEADER_MAP

MAP - UTF MISS
  Scan File  ${MESSAGE}
  ...   Settings={symbols_enabled = [HEADER_MAP]}
  Do Not Expect Symbol  HEADER_MAP

MAP - HOSTNAME
  Scan File  ${MESSAGE}  IP=127.0.0.1  Hostname=example.com
  ...   Settings={symbols_enabled = [HOSTNAME_MAP]}
  Expect Symbol  HOSTNAME_MAP

MAP - HOSTNAME MISS
  Scan File  ${MESSAGE}  IP=127.0.0.1  Hostname=rspamd.com
  ...   Settings={symbols_enabled = [HOSTNAME_MAP]}
  Do Not Expect Symbol  HOSTNAME_MAP

MAP - TOP
  Scan File  ${MESSAGE}  IP=127.0.0.1  Hostname=example.com.au
  ...   Settings={symbols_enabled = [HOSTNAME_TOP_MAP]}
  Expect Symbol  HOSTNAME_TOP_MAP

MAP - TOP MISS
  Scan File  ${MESSAGE}  IP=127.0.0.1  Hostname=example.com.bg
  ...   Settings={symbols_enabled = [HOSTNAME_TOP_MAP]}
  Do Not Expect Symbol  HOSTNAME_TOP_MAP

MAP - CDB - HOSTNAME
  Scan File  ${MESSAGE}  IP=127.0.0.1  Hostname=example.com
  ...   Settings={symbols_enabled = [CDB_HOSTNAME]}
  Expect Symbol  CDB_HOSTNAME

MAP - CDB - HOSTNAME MISS
  Scan File  ${MESSAGE}  IP=127.0.0.1  Hostname=rspamd.com
  ...   Settings={symbols_enabled = [CDB_HOSTNAME]}
  Do Not Expect Symbol  CDB_HOSTNAME

MAP - REDIS - HOSTNAME
  Redis HSET  hostname  redistest.example.net  ${EMPTY}
  Scan File  ${MESSAGE}  IP=127.0.0.1  Hostname=redistest.example.net
  ...   Settings={symbols_enabled = [REDIS_HOSTNAME]}
  Expect Symbol  REDIS_HOSTNAME

MAP - REDIS - HOSTNAME MISS
  Scan File  ${MESSAGE}  IP=127.0.0.1  Hostname=rspamd.com
  ...   Settings={symbols_enabled = [REDIS_HOSTNAME]}
  Do Not Expect Symbol  REDIS_HOSTNAME

MAP - REDIS - HOSTNAME - EXPANSION - HIT
  Redis HSET  127.0.0.1.foo.com  redistest.example.net  ${EMPTY}
  Scan File  ${MESSAGE}  IP=127.0.0.1  Hostname=redistest.example.net  Rcpt=bob@foo.com
  ...   Settings={symbols_enabled = [REDIS_HOSTNAME_EXPANSION]}
  Expect Symbol  REDIS_HOSTNAME_EXPANSION

MAP - REDIS - HOSTNAME - EXPANSION - MISS
  Scan File  ${MESSAGE}  IP=127.0.0.1  Hostname=redistest.example.net  Rcpt=bob@bar.com
  ...   Settings={symbols_enabled = [REDIS_HOSTNAME_EXPANSION]}
  Do Not Expect Symbol  REDIS_HOSTNAME_EXPANSION

MAP - REDIS - IP
  Redis HSET  ipaddr  127.0.0.1  ${EMPTY}
  Scan File  ${MESSAGE}  IP=127.0.0.1
  ...   Settings={symbols_enabled = [REDIS_IPADDR]}
  Expect Symbol  REDIS_IPADDR

MAP - REDIS - IP - MISS
  Scan File  ${MESSAGE}  IP=8.8.8.8
  ...   Settings={symbols_enabled = [REDIS_IPADDR]}
  Do Not Expect Symbol  REDIS_IPADDR

MAP - REDIS - FROM
  Redis HSET  emailaddr  from@rspamd.tk  ${EMPTY}
  Scan File  ${MESSAGE}  From=from@rspamd.tk
  ...   Settings={symbols_enabled = [REDIS_FROMADDR]}
  Expect Symbol  REDIS_FROMADDR

MAP - REDIS - FROM MISS
  Scan File  ${MESSAGE}  From=user@other.com
  ...   Settings={symbols_enabled = [REDIS_FROMADDR]}
  Do Not Expect Symbol  REDIS_FROMADDR

MAP - REDIS - URL TLD - HIT
  Redis HSET  hostname  example.com  ${EMPTY}
  Scan File  ${URL1}
  ...   Settings={symbols_enabled = [REDIS_URL_TLD]}
  Expect Symbol  REDIS_URL_TLD

MAP - REDIS - URL TLD - MISS
  Scan File  ${URL2}
  ...   Settings={symbols_enabled = [REDIS_URL_TLD]}
  Do Not Expect Symbol  REDIS_URL_TLD

MAP - REDIS - URL RE FULL - HIT
  Redis HSET  fullurlre  html  ${EMPTY}
  Scan File  ${URL2}
  ...   Settings={symbols_enabled = [REDIS_URL_RE_FULL]}
  Expect Symbol  REDIS_URL_RE_FULL

MAP - REDIS - URL RE FULL - MISS
  Scan File  ${URL1}
  ...   Settings={symbols_enabled = [REDIS_URL_RE_FULL]}
  Do Not Expect Symbol  REDIS_URL_RE_FULL

MAP - REDIS - URL FULL - HIT
  Redis HSET  fullurl  https://www.example.com/foo?a=b  ${EMPTY}
  Scan File  ${URL1}
  ...   Settings={symbols_enabled = [REDIS_URL_FULL]}
  Expect Symbol  REDIS_URL_FULL

MAP - REDIS - URL FULL - MISS
  Scan File  ${URL2}
  ...   Settings={symbols_enabled = [REDIS_URL_FULL]}
  Do Not Expect Symbol  REDIS_URL_FULL

MAP - REDIS - URL PHISHED - HIT
  Redis HSET  phishedurl  www.rspamd.com  ${EMPTY}
  Scan File  ${URL3}
  ...   Settings={symbols_enabled = [REDIS_URL_PHISHED]}
  Expect Symbol  REDIS_URL_PHISHED

MAP - REDIS - URL PHISHED - MISS
  Scan File  ${URL4}
  ...   Settings={symbols_enabled = [REDIS_URL_PHISHED]}
  Do Not Expect Symbol  REDIS_URL_PHISHED

MAP - REDIS - URL PLAIN REGEX - HIT
  Redis HSET  urlre  www  ${EMPTY}
  Scan File  ${URL3}
  ...   Settings={symbols_enabled = [REDIS_URL_RE_PLAIN]}
  Expect Symbol  REDIS_URL_RE_PLAIN

MAP - REDIS - URL PLAIN REGEX - MISS
  Scan File  ${URL4}
  ...   Settings={symbols_enabled = [REDIS_URL_RE_PLAIN]}
  Do Not Expect Symbol  REDIS_URL_RE_PLAIN

MAP - REDIS - URL TLD REGEX - HIT
  Redis HSET  tldre  net  ${EMPTY}
  Scan File  ${URL5}
  ...   Settings={symbols_enabled = [REDIS_URL_RE_TLD]}
  Expect Symbol  REDIS_URL_RE_TLD

MAP - REDIS - URL TLD REGEX - MISS
  Scan File  ${URL4}
  ...   Settings={symbols_enabled = [REDIS_URL_RE_TLD]}
  Do Not Expect Symbol  REDIS_URL_RE_TLD

MAP - REDIS - URL NOFILTER - HIT
  Redis HSET  urlnofilter  www.example.net  ${EMPTY}
  Scan File  ${URL5}
  ...   Settings={symbols_enabled = [REDIS_URL_NOFILTER]}
  Expect Symbol  REDIS_URL_NOFILTER

MAP - REDIS - URL NOFILTER - MISS
  Scan File  ${URL4}
  ...   Settings={symbols_enabled = [REDIS_URL_NOFILTER]}
  Do Not Expect Symbol  REDIS_URL_NOFILTER

MAP - REDIS - ASN - HIT
  Redis HSET  asn  15169  ${EMPTY}
  Scan File  ${MESSAGE}  IP=8.8.8.8
  ...   Settings={symbols_enabled = [REDIS_ASN, ASN_CHECK]}
  Expect Symbol  REDIS_ASN

MAP - REDIS - ASN - MISS
  Scan File  ${MESSAGE}  IP=46.228.47.114
  ...   Settings={symbols_enabled = [REDIS_ASN, ASN_CHECK]}
  Do Not Expect Symbol  REDIS_ASN

MAP - REDIS - CC - HIT
  Redis HSET  cc  US  ${EMPTY}
  Scan File  ${MESSAGE}  IP=8.8.8.8
  ...   Settings={symbols_enabled = [REDIS_COUNTRY, ASN_CHECK]}
  Expect Symbol  REDIS_COUNTRY

MAP - REDIS - CC - MISS
  Scan File  ${MESSAGE}  IP=46.228.47.114
  ...   Settings={symbols_enabled = [REDIS_COUNTRY, ASN_CHECK]}
  Do Not Expect Symbol  REDIS_COUNTRY

MAP - REDIS - ASN FILTERED - HIT
  Redis HSET  asn  1  ${EMPTY}
  Scan File  ${MESSAGE}  IP=8.8.8.8
  ...   Settings={symbols_enabled = [REDIS_ASN_FILTERED, ASN_CHECK]}
  Expect Symbol  REDIS_ASN_FILTERED

MAP - REDIS - ASN FILTERED - MISS
  Scan File  ${MESSAGE}  IP=46.228.47.114
  ...   Settings={symbols_enabled = [REDIS_ASN_FILTERED, ASN_CHECK]}
  Do Not Expect Symbol  REDIS_ASN_FILTERED

MAP - RECEIVED - IP MINMAX POS - ONE
  Scan File  ${RCVD1}
  ...   Settings={symbols_enabled = [RCVD_TEST_01, RCVD_TEST02]}
  Expect Symbol  RCVD_TEST_01
  Do Not Expect Symbol  RCVD_TEST_02

# Relies on parsing of shitty received
#MAP - RECEIVED - IP MINMAX POS - TWO / RCVD_AUTHED_ONE HIT
#  Scan File  ${RCVD2}
#  Expect Symbol  RCVD_TEST_02
#  Do Not Expect Symbol  RCVD_TEST_01
#  Expect Symbol  RCVD_AUTHED_ONE

MAP - RECEIVED - REDIS
  Redis HSET  RCVD_TEST  2a01:7c8:aab6:26d:5054:ff:fed1:1da2  ${EMPTY}
  Scan File  ${RCVD1}
  ...   Settings={symbols_enabled = [RCVD_TEST_REDIS_01]}
  Expect Symbol  RCVD_TEST_REDIS_01

RCVD_AUTHED_ONE & RCVD_AUTHED_TWO - MISS
  Scan File  ${RCVD3}
  ...   Settings={symbols_enabled = [RCVD_AUTHED_ONE, RCVD_AUTHED_TWO]}
  Do Not Expect Symbol  RCVD_AUTHED_ONE
  Do Not Expect Symbol  RCVD_AUTHED_TWO

RCVD_AUTHED_TWO HIT / RCVD_AUTHED_ONE MISS
  Scan File  ${RCVD4}
  ...   Settings={symbols_enabled = [RCVD_AUTHED_ONE, RCVD_AUTHED_TWO]}
  Expect Symbol  RCVD_AUTHED_TWO
  Do Not Expect Symbol  RCVD_AUTHED_ONE

FREEMAIL_CC
  Scan File  ${FREEMAIL_CC}
  ...   Settings={symbols_enabled = [FREEMAIL_CC]}
  Expect Symbol With Score And Exact Options  FREEMAIL_CC  19.00  test.com  test1.com  test2.com  test3.com  test4.com  test5.com  test6.com  test7.com  test8.com  test9.com  test10.com  test11.com  test12.com  test13.com  test14.com

MAP - MULTISYMBOL DISABLED
  Scan File  ${MESSAGE}  Rcpt=user3@example.com
  ...   Settings={symbols_enabled = [RCPT_MAP_NOMULTISYM, SYM1]}
  Expect Symbol With Exact Options  RCPT_MAP_NOMULTISYM  user3@example.com  SYM1
