*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}               ${RSPAMD_TESTDIR}/configs/chartable.conf
${RSPAMD_SCOPE}         Suite
${RSPAMD_URL_TLD}       ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${SETTINGS_CHARTABLE}   {symbols_enabled = [R_MIXED_CHARSET,TEST_LANGUAGE]}

*** Test Cases ***
Language data marks diacritic languages
  FOR  ${language}  IN  hr  sr  sq  is  ga  cy  eu  sk
    ${content} =  Get File  ${RSPAMD_INSTALLROOT}/share/rspamd/languages/${language}.json
    ${data} =  Evaluate  json.loads($content)  modules=json
    List Should Contain Value  ${data}[flags]  diacritics
  END

Slovak diacritics are ignored
  Scan File  ${RSPAMD_TESTDIR}/messages/chartable_slovak.eml
  ...  Settings=${SETTINGS_CHARTABLE}
  Expect Symbol With Option  TEST_LANGUAGE  sk
  Do Not Expect Symbol  R_MIXED_CHARSET

English diacritics are significant
  Scan File  ${RSPAMD_TESTDIR}/messages/chartable_english_diacritics.eml
  ...  Settings=${SETTINGS_CHARTABLE}
  Expect Symbol With Option  TEST_LANGUAGE  en
  Expect Symbol  R_MIXED_CHARSET

Combining marks do not hide mixed scripts
  Scan File  ${RSPAMD_TESTDIR}/messages/chartable_serbian_combining.eml
  ...  Settings=${SETTINGS_CHARTABLE}
  Expect Symbol With Option  TEST_LANGUAGE  sr
  Expect Symbol  R_MIXED_CHARSET

Multipart language state does not leak into subject
  Scan File  ${RSPAMD_TESTDIR}/messages/chartable_multipart_subject.eml
  ...  Settings=${SETTINGS_CHARTABLE}
  Expect Symbol With Option  TEST_LANGUAGE  sk
  Expect Symbol With Option  TEST_LANGUAGE  en
  Do Not Expect Symbol  R_MIXED_CHARSET
