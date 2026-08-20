*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${SETTINGS_SPF}    {symbols_enabled = [SPF_CHECK]}

*** Test Cases ***
SPF FAIL UNRESOLVEABLE INCLUDE
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=37.48.67.26  From=x@fail3.org.org.za
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_FAIL

SPF DNSFAIL FAILED INCLUDE UNALIGNED
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=8.8.8.8  From=x@fail2.org.org.za
  ...  Settings={symbols_enabled = [SPF_CHECK,DKIM_CHECK,DMARC_CHECK]}
  Expect Symbol  R_SPF_DNSFAIL
  Expect Symbol  DMARC_POLICY_SOFTFAIL

SPF ALLOW UNRESOLVEABLE INCLUDE
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=8.8.8.8  From=x@fail3.org.org.za
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_ALLOW

SPF ALLOW FAILED INCLUDE
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=8.8.4.4  From=x@fail2.org.org.za
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_ALLOW

SPF NA NA
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=8.8.8.8  From=x@za
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_NA

SPF NA NOREC
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=8.8.8.8  From=x@co.za
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_NA

SPF NA NXDOMAIN
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=8.8.8.8  From=x@zzzzaaaa
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_NA

SPF NA HELO IP LITERAL
  [Documentation]  HELO IP address literals must yield R_SPF_NA, not R_SPF_DNSFAIL (RFC 7208 §2.3)
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=8.8.8.8  From=<>  Helo=[10.88.0.3]
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_NA
  Do Not Expect Symbol  R_SPF_DNSFAIL

SPF PERMFAIL UNRESOLVEABLE REDIRECT
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=8.8.8.8  From=x@fail4.org.org.za
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_PERMFAIL

SPF REDIRECT NO USEABLE ELEMENTS
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=8.8.8.8  From=x@fail10.org.org.za
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_PERMFAIL

SPF DNSFAIL FAILED REDIRECT
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=8.8.8.8  From=x@fail1.org.org.za
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_DNSFAIL

SPF PERMFAIL NO USEABLE ELEMENTS
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=8.8.8.8  From=x@fail5.org.org.za
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_PERMFAIL

SPF FAIL
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=8.8.8.8  From=x@example.net
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_FAIL

SPF FAIL UNRESOLVEABLE MX
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=1.2.3.4  From=x@fail6.org.org.za
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_FAIL

SPF FAIL UNRESOLVEABLE A
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=1.2.3.4  From=x@fail7.org.org.za
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_FAIL

SPF DNSFAIL FAILED A
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=1.2.3.4  From=x@fail8.org.org.za
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_DNSFAIL

SPF DNSFAIL FAILED MX
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=1.2.3.4  From=x@fail9.org.org.za
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_DNSFAIL

SPF DNSFAIL FAILED RECORD
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=1.2.3.4  From=x@www.dnssec-failed.org
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_DNSFAIL

SPF PASS INCLUDE
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=8.8.8.8  From=x@pass1.org.org.za
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_ALLOW

SPF PTRS
  Scan File  /dev/null
  ...  IP=88.99.142.95  From=foo@crazyspf.cacophony.za.org
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_ALLOW
  Scan File  /dev/null
  ...  IP=128.66.0.1  From=foo@crazyspf.cacophony.za.org
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_FAIL
  Scan File  /dev/null
  ...  IP=209.85.216.182  From=foo@crazyspf.cacophony.za.org
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_FAIL
  #Scan File  /dev/null
  #...  IP=98.138.91.166  From=foo@crazyspf.cacophony.za.org
  #Expect Symbol  R_SPF_ALLOW
  #Scan File  /dev/null
  #...  IP=98.138.91.167  From=foo@crazyspf.cacophony.za.org
  #Expect Symbol  R_SPF_ALLOW
  #Scan File  /dev/null
  #...  IP=98.138.91.168  From=foo@crazyspf.cacophony.za.org
  #Expect Symbol  R_SPF_ALLOW

SPF PERMFAIL REDIRECT WITHOUT SPF
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim4.eml
  ...  IP=192.0.2.1  From=a@fail1.org.org.za
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_DNSFAIL

SPF EXTERNAL RELAY
  Scan File  ${RSPAMD_TESTDIR}/messages/external_relay.eml
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol With Score And Exact Options  R_SPF_ALLOW  -0.2  +ip4:37.48.67.26

SPF UPPERCASE
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=8.8.8.8  From=x@fail11.org.org.za
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_ALLOW

SPF PLUSALL
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=8.8.8.8  From=x@plusall.com
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_PLUSALL

SPF PERMFAIL MULTIPLE RECORDS
  [Documentation]  RFC 7208 4.5: more than one SPF record yields permerror. An
  ...  RRset has no order, so evaluating either of them would tie the verdict to
  ...  the order the resolver answered in, even though 8.8.8.8 is authorised by
  ...  the first one
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=8.8.8.8  From=x@twospf.org.org.za
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_PERMFAIL
  Do Not Expect Symbol  R_SPF_ALLOW
  Do Not Expect Symbol  R_SPF_FAIL

SPF ALLOW ONE RECORD AMONG OTHER TXT
  [Documentation]  Only records starting with the v=spf1 version string count
  ...  towards that limit, an unrelated TXT record alongside one SPF record is
  ...  the common case and must still be evaluated
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=8.8.8.8  From=x@onespf.org.org.za
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_ALLOW
  Do Not Expect Symbol  R_SPF_PERMFAIL

SPF ALLOW MX
  [Documentation]  A normal mx element is expanded to the addresses of its names
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=8.8.8.8  From=x@fewmx.org.org.za
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_ALLOW

SPF PERMFAIL TOO MANY MX NAMES
  [Documentation]  RFC 7208 4.6.4: an mx element must not query more than 10
  ...  address records, exceeding that limit yields permerror
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=8.8.8.8  From=x@manymx.org.org.za
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_PERMFAIL
  Do Not Expect Symbol  R_SPF_FAIL

SPF ALLOW NESTING AT LIMIT
  [Documentation]  An include chain is followed up to max_dns_nesting levels
  ...  (10 by default), 8.8.8.8 is listed by the last allowed one
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=8.8.8.8  From=x@nestok.org.org.za
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_ALLOW

SPF PERMFAIL NESTING BEYOND LIMIT
  [Documentation]  The same chain entered one level deeper cannot be evaluated
  ...  to the end, which is permerror per RFC 7208 4.6.4 rather than a fail
  ...  based on the part of the record that fitted in the limit
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=8.8.8.8  From=x@nestdeep.org.org.za
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_PERMFAIL
  Do Not Expect Symbol  R_SPF_ALLOW
  Do Not Expect Symbol  R_SPF_FAIL

SPF ALLOW EXISTS
  [Documentation]  RFC 7208 5.7: an exists element whose name resolves matches
  ...  any sender, here it follows an include that has appended an element of
  ...  its own to the record
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=8.8.8.8  From=x@exists.org.org.za
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_ALLOW

SPF FAIL UNRESOLVEABLE EXISTS
  [Documentation]  An exists element whose name does not resolve matches
  ...  nothing, so the trailing -all applies
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=8.8.8.8  From=x@noexists.org.org.za
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_FAIL
  Do Not Expect Symbol  R_SPF_ALLOW

SPF ALLOW DNS REQUESTS AT LIMIT
  [Documentation]  Exactly max_dns_requests DNS elements (30 by default) are
  ...  evaluated, here the last of them authorises 8.8.8.8
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=8.8.8.8  From=x@fewreq.org.org.za
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_ALLOW

SPF PERMFAIL DNS REQUESTS BEYOND LIMIT
  [Documentation]  RFC 7208 4.6.4: a record with one DNS element more than the
  ...  limit allows cannot be evaluated to the end and yields permerror
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  IP=8.8.8.8  From=x@manyreq.org.org.za
  ...  Settings=${SETTINGS_SPF}
  Expect Symbol  R_SPF_PERMFAIL
  Do Not Expect Symbol  R_SPF_ALLOW
  Do Not Expect Symbol  R_SPF_FAIL
