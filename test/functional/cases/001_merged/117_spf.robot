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
