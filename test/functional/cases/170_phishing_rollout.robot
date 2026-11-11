*** Settings ***
Suite Setup     Rollout Setup
Suite Teardown  Rollout Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}        ${RSPAMD_TESTDIR}/configs/phishing_rollout.conf
${RSPAMD_SCOPE}  Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${SETTINGS}      {symbols_enabled=[PHISHING,PHISHING_QUERY,URL_DISPLAY_MISMATCH,PHISHING_REWRITE_ALLOWED,REDIRECTOR_FALSE]}

*** Test Cases ***
LEGACY REDIRECTOR EXEMPTION REMAINS OBSERVABLE
  Scan Rollout Link  https://t.co/opaque
  Expect Symbol With Score  REDIRECTOR_FALSE  0
  Expect Symbol With Score  URL_DISPLAY_MISMATCH  0
  Do Not Expect Symbol  PHISHING
  Do Not Expect Symbol  PHISHING_REWRITE_ALLOWED

SHIPPED PROOFPOINT V3 WRAPPER IS TRUSTED
  Scan Rollout Link  https://urldefense.com/opaque
  Expect Rollout Trust

SHIPPED PROOFPOINT V2 WRAPPER IS TRUSTED
  Scan Rollout Link  https://urldefense.proofpoint.com/opaque
  Expect Rollout Trust

SHIPPED SAFE LINKS NAMESPACE IS TRUSTED
  Scan Rollout Link  https://nam01.safelinks.protection.outlook.com/opaque
  Expect Rollout Trust

SHIPPED MIMECAST US WRAPPER IS TRUSTED
  Scan Rollout Link  https://url.us.m.mimecastprotect.com/opaque
  Expect Rollout Trust

SHIPPED MIMECAST UK WRAPPER IS TRUSTED
  Scan Rollout Link  https://url.uk.m.mimecastprotect.com/opaque
  Expect Rollout Trust

SHIPPED BARRACUDA WRAPPER IS TRUSTED
  Scan Rollout Link  https://linkprotect.cudasvc.com/opaque
  Expect Rollout Trust

SHIPPED CISCO WRAPPER IS TRUSTED
  Scan Rollout Link  https://secure-web.cisco.com/opaque
  Expect Rollout Trust

SHIPPED EXACT WRAPPERS DO NOT TRUST PARENT OR SIBLING HOSTS
  [Template]  Expect No Rollout Trust
  mimecastprotect.com
  other.us.m.mimecastprotect.com
  other.cudasvc.com
  other.cisco.com

SHIPPED EXACT WRAPPERS DO NOT TRUST SUBDOMAINS
  [Template]  Expect No Rollout Trust
  extra.url.us.m.mimecastprotect.com
  extra.url.uk.m.mimecastprotect.com
  extra.linkprotect.cudasvc.com
  extra.secure-web.cisco.com

SHIPPED EXACT WRAPPERS DO NOT TRUST SUFFIX LOOKALIKES
  [Template]  Expect No Rollout Trust
  url.us.m.mimecastprotect.com.attacker.org
  url.uk.m.mimecastprotect.com.attacker.org
  linkprotect.cudasvc.com.attacker.org
  secure-web.cisco.com.attacker.org

SHIPPED MAP DOES NOT TRUST OTHER PROOFPOINT HOSTS
  Scan Rollout Link  https://other.proofpoint.com/opaque
  Do Not Expect Symbol  PHISHING_REWRITE_ALLOWED

SHIPPED MAP DOES NOT TRUST SAFE LINKS SUFFIX LOOKALIKES
  Scan Rollout Link  https://nam01.safelinks.protection.outlook.com.attacker.org/opaque
  Expect Symbol  PHISHING
  Do Not Expect Symbol  PHISHING_REWRITE_ALLOWED

EMPTY PAIR MAP FALLBACKS DO NOT ALLOW UNREVIEWED REWRITES
  Scan Rollout Link  https://unreviewed-wrapper.example.net/opaque
  Expect Symbol  PHISHING
  Do Not Expect Symbol  PHISHING_REWRITE_ALLOWED

*** Keywords ***
Rollout Setup
  ${original_mirror} =  Get Environment Variable  RSPAMD_MAPS_MIRROR  ${EMPTY}
  Set Suite Variable  ${ORIGINAL_MAPS_MIRROR}  ${original_mirror}
  # An unavailable loopback mirror forces the stock maps to use their packaged
  # fallbacks without depending on any public map service.
  Set Environment Variable  RSPAMD_MAPS_MIRROR  http://127.0.0.1:1
  Rspamd Setup

Rollout Teardown
  Rspamd Teardown
  IF  $ORIGINAL_MAPS_MIRROR
    Set Environment Variable  RSPAMD_MAPS_MIRROR  ${ORIGINAL_MAPS_MIRROR}
  ELSE
    Remove Environment Variable  RSPAMD_MAPS_MIRROR
  END

Scan Rollout Link
  [Arguments]  ${href}
  ${message} =  Set Variable  ${RSPAMD_TMPDIR}/phishing-rollout.eml
  Create File  ${message}  Content-Type: text/html; charset=utf-8\n\n<a href="${href}">https://www.cnn.com/</a>
  Scan File  ${message}  Settings=${SETTINGS}

Expect No Rollout Trust
  [Arguments]  ${host}
  Scan Rollout Link  https://${host}/opaque
  Expect Symbol With Score  URL_DISPLAY_MISMATCH  0
  Do Not Expect Symbol  PHISHING_REWRITE_ALLOWED

Expect Rollout Trust
  Expect Symbol With Score  PHISHING_REWRITE_ALLOWED  0
  Expect Symbol With Score  URL_DISPLAY_MISMATCH  0
  Do Not Expect Symbol  PHISHING
  Do Not Expect Symbol  PHISHING_QUERY
  Do Not Expect Symbol  REDIRECTOR_FALSE
