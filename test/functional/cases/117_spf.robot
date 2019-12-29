*** Settings ***
Suite Setup     SPF Setup
Suite Teardown  Simple Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}        ${TESTDIR}/configs/plugins.conf
${RSPAMD_SCOPE}  Suite
${URL_TLD}       ${TESTDIR}/../../contrib/publicsuffix/effective_tld_names.dat

*** Test Cases ***
SPF FAIL UNRESOLVEABLE INCLUDE
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  -i  37.48.67.26  -F  x@fail3.org.org.za
  Check Rspamc  ${result}  R_SPF_FAIL

SPF DNSFAIL FAILED INCLUDE UNALIGNED
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  -i  8.8.8.8  -F  x@fail2.org.org.za
  Check Rspamc  ${result}  R_SPF_DNSFAIL
  Should Contain  ${result.stdout}  DMARC_POLICY_SOFTFAIL

SPF ALLOW UNRESOLVEABLE INCLUDE
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  -i  8.8.8.8  -F  x@fail3.org.org.za
  Check Rspamc  ${result}  R_SPF_ALLOW

SPF ALLOW FAILED INCLUDE
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  -i  8.8.4.4  -F  x@fail2.org.org.za
  Check Rspamc  ${result}  R_SPF_ALLOW

SPF NA NA
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  -i  8.8.8.8  -F  x@za
  Check Rspamc  ${result}  R_SPF_NA

SPF NA NOREC
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  -i  8.8.8.8  -F  x@co.za
  Check Rspamc  ${result}  R_SPF_NA

SPF NA NXDOMAIN
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  -i  8.8.8.8  -F  x@zzzzaaaa
  Check Rspamc  ${result}  R_SPF_NA

SPF PERMFAIL UNRESOLVEABLE REDIRECT
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  -i  8.8.8.8  -F  x@fail4.org.org.za
  Check Rspamc  ${result}  R_SPF_PERMFAIL

SPF REDIRECT NO USEABLE ELEMENTS
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  -i  8.8.8.8  -F  x@fail10.org.org.za
  Check Rspamc  ${result}  R_SPF_PERMFAIL

SPF DNSFAIL FAILED REDIRECT
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  -i  8.8.8.8  -F  x@fail1.org.org.za
  Check Rspamc  ${result}  R_SPF_DNSFAIL

SPF PERMFAIL NO USEABLE ELEMENTS
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  -i  8.8.8.8  -F  x@fail5.org.org.za
  Check Rspamc  ${result}  R_SPF_PERMFAIL

SPF FAIL
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  -i  8.8.8.8  -F  x@example.net
  Check Rspamc  ${result}  R_SPF_FAIL

SPF FAIL UNRESOLVEABLE MX
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  -i  1.2.3.4  -F  x@fail6.org.org.za
  Check Rspamc  ${result}  R_SPF_FAIL

SPF FAIL UNRESOLVEABLE A
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  -i  1.2.3.4  -F  x@fail7.org.org.za
  Check Rspamc  ${result}  R_SPF_FAIL

SPF DNSFAIL FAILED A
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  -i  1.2.3.4  -F  x@fail8.org.org.za
  Check Rspamc  ${result}  R_SPF_DNSFAIL

SPF DNSFAIL FAILED MX
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  -i  1.2.3.4  -F  x@fail9.org.org.za
  Check Rspamc  ${result}  R_SPF_DNSFAIL

SPF DNSFAIL FAILED RECORD
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  -i  1.2.3.4  -F  x@www.dnssec-failed.org
  Check Rspamc  ${result}  R_SPF_DNSFAIL

SPF PASS INCLUDE
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  -i  8.8.8.8  -F  x@pass1.org.org.za
  Check Rspamc  ${result}  R_SPF_ALLOW

SPF PTRS
  ${result} =  Scan Message With Rspamc  /dev/null
  ...  -i  88.99.142.95  -F  foo@crazyspf.cacophony.za.org
  Check Rspamc  ${result}  R_SPF_ALLOW
  ${result} =  Scan Message With Rspamc  /dev/null
  ...  -i  128.66.0.1  -F  foo@crazyspf.cacophony.za.org
  Check Rspamc  ${result}  R_SPF_FAIL
  ${result} =  Scan Message With Rspamc  /dev/null
  ...  -i  209.85.216.182  -F  foo@crazyspf.cacophony.za.org
  Check Rspamc  ${result}  R_SPF_FAIL
  #${result} =  Scan Message With Rspamc  /dev/null
  #...  -i  98.138.91.166  -F  foo@crazyspf.cacophony.za.org
  #Check Rspamc  ${result}  R_SPF_ALLOW
  #${result} =  Scan Message With Rspamc  /dev/null
  #...  -i  98.138.91.167  -F  foo@crazyspf.cacophony.za.org
  #Check Rspamc  ${result}  R_SPF_ALLOW
  #${result} =  Scan Message With Rspamc  /dev/null
  #...  -i  98.138.91.168  -F  foo@crazyspf.cacophony.za.org
  #Check Rspamc  ${result}  R_SPF_ALLOW

SPF PERMFAIL REDIRECT WITHOUT SPF
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/bad_dkim4.eml
  ...  -i  192.0.2.1  -F  a@fail1.org.org.za
  Check Rspamc  ${result}  R_SPF_DNSFAIL

SPF EXTERNAL RELAY
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/external_relay.eml
  Should contain  ${result.stdout}  R_SPF_ALLOW (1.00)[+ip4:37.48.67.26]

SPF UPPERCASE
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  -i  8.8.8.8  -F  x@fail11.org.org.za
  Check Rspamc  ${result}  R_SPF_ALLOW

*** Keywords ***
SPF Setup
  ${PLUGIN_CONFIG} =  Get File  ${TESTDIR}/configs/dmarc.conf
  Set Suite Variable  ${PLUGIN_CONFIG}
  Generic Setup  PLUGIN_CONFIG
