*** Settings ***
Suite Setup     DMARC Setup
Suite Teardown  Simple Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}        ${TESTDIR}/configs/plugins.conf
${RSPAMD_SCOPE}  Suite
${URL_TLD}       ${TESTDIR}/../../contrib/publicsuffix/effective_tld_names.dat

*** Test Cases ***
DMARC NONE PASS DKIM
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/pass_none.eml
  Check Rspamc  ${result}  DMARC_POLICY_ALLOW

DMARC NONE PASS SPF
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/fail_none.eml
  ...  -i  8.8.4.4  --from  foo@spf.cacophony.za.org
  Check Rspamc  ${result}  DMARC_POLICY_ALLOW

DMARC NONE FAIL
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/fail_none.eml
  Check Rspamc  ${result}  DMARC_POLICY_SOFTFAIL

DMARC REJECT FAIL
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/fail_reject.eml
  Check Rspamc  ${result}  DMARC_POLICY_REJECT

DMARC QUARANTINE FAIL
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/fail_quarantine.eml
  Check Rspamc  ${result}  DMARC_POLICY_QUARANTINE

DMARC SP NONE FAIL
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/subdomain_fail_none.eml
  Check Rspamc  ${result}  DMARC_POLICY_SOFTFAIL

DMARC SP REJECT FAIL
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/subdomain_fail_reject.eml
  Check Rspamc  ${result}  DMARC_POLICY_REJECT

DMARC SP QUARANTINE FAIL
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/subdomain_fail_quarantine.eml
  Check Rspamc  ${result}  DMARC_POLICY_QUARANTINE

DMARC SUBDOMAIN FAIL DKIM STRICT ALIGNMENT
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/onsubdomain_fail_alignment.eml
  Check Rspamc  ${result}  DMARC_POLICY_REJECT

DMARC SUBDOMAIN PASS DKIM RELAXED ALIGNMENT
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/onsubdomain_pass_relaxed.eml
  Check Rspamc  ${result}  DMARC_POLICY_ALLOW

DMARC SUBDOMAIN PASS SPF STRICT ALIGNMENT
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/onsubdomain_fail_alignment.eml
  ...  -i  37.48.67.26  --from  foo@yo.mom.za.org
  Check Rspamc  ${result}  DMARC_POLICY_ALLOW

DMARC SUBDOMAIN FAIL SPF STRICT ALIGNMENT
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/onsubdomain_fail_alignment.eml
  ...  -i  37.48.67.26  --from  foo@mom.za.org
  Check Rspamc  ${result}  DMARC_POLICY_REJECT

DMARC SUBDOMAIN PASS SPF RELAXED ALIGNMENT
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/onsubdomain_fail.eml
  ...  -i  37.48.67.26  --from  foo@mom.za.org
  Check Rspamc  ${result}  DMARC_POLICY_ALLOW

DMARC DNSFAIL
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/dmarc_tmpfail.eml
  ...  -i  37.48.67.26  --from  foo@mom.za.org
  Check Rspamc  ${result}  DMARC_DNSFAIL

DMARC NA NXDOMAIN
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/utf.eml
  ...  -i  37.48.67.26  --from  foo@mom.za.org
  Check Rspamc  ${result}  DMARC_NA

DMARC PCT ZERO REJECT
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/pct_none.eml
  ...  -i  37.48.67.26  --from  foo@mom.za.org
  Check Rspamc  ${result}  DMARC_POLICY_QUARANTINE

DMARC PCT ZERO SP QUARANTINE
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/pct_none1.eml
  ...  -i  37.48.67.26  --from  foo@mom.za.org
  Check Rspamc  ${result}  DMARC_POLICY_SOFTFAIL

DKIM PERMFAIL NXDOMAIN
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/bad_dkim2.eml
  ...  -i  37.48.67.26
  Check Rspamc  ${result}  R_DKIM_PERMFAIL

DKIM PERMFAIL BAD RECORD
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  -i  37.48.67.26
  Check Rspamc  ${result}  R_DKIM_PERMFAIL

DKIM TEMPFAIL SERVFAIL UNALIGNED
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/bad_dkim3.eml
  ...  -i  37.48.67.26
  Check Rspamc  ${result}  R_DKIM_TEMPFAIL
  Should Contain  ${result.stdout}  DMARC_POLICY_SOFTFAIL

DKIM NA NOSIG
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/utf.eml
  ...  -i  37.48.67.26
  Check Rspamc  ${result}  R_DKIM_NA

SPF PERMFAIL UNRESOLVEABLE INCLUDE
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  -i  37.48.67.26  -F  x@fail3.org.org.za
  Check Rspamc  ${result}  R_SPF_PERMFAIL

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

SPF PERMFAIL UNRESOLVEABLE MX
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  -i  1.2.3.4  -F  x@fail6.org.org.za
  Check Rspamc  ${result}  R_SPF_PERMFAIL

SPF PERMFAIL UNRESOLVEABLE A
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/dmarc/bad_dkim1.eml
  ...  -i  1.2.3.4  -F  x@fail7.org.org.za
  Check Rspamc  ${result}  R_SPF_PERMFAIL

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
  Check Rspamc  ${result}  R_SPF_PERMFAIL
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

*** Keywords ***
DMARC Setup
  ${PLUGIN_CONFIG} =  Get File  ${TESTDIR}/configs/dmarc.conf
  Set Suite Variable  ${PLUGIN_CONFIG}
  Generic Setup  PLUGIN_CONFIG
