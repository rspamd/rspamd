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
${SETTINGS_CHARTABLE}   {symbols_enabled = [R_MIXED_CHARSET,R_MIXED_CHARSET_URL,TEST_LANGUAGE,TEST_CHARTABLE_WORDS]}

*** Test Cases ***
Language data marks diacritic languages
  FOR  ${language}  IN  hr  sr  sq  is  ga  cy  eu  sk  hi  mr  ne  bn  pa  ur  ar  fa
    ${content} =  Get File  ${RSPAMD_INSTALLROOT}/share/rspamd/languages/${language}.json
    ${data} =  Evaluate  json.loads($content)  modules=json
    List Should Contain Value  ${data}[flags]  diacritics
  END

Slovak diacritics are ignored
  Scan File  ${RSPAMD_TESTDIR}/messages/chartable_slovak.eml
  ...  Settings=${SETTINGS_CHARTABLE}
  Expect Symbol With Option  TEST_LANGUAGE  sk
  Do Not Expect Symbol  R_MIXED_CHARSET

Hindi vowel signs are ignored
  Scan File  ${RSPAMD_TESTDIR}/messages/chartable_hindi.eml
  ...  Settings=${SETTINGS_CHARTABLE}
  Expect Symbol  TEST_LANGUAGE
  ${languages} =  Convert To List  ${SCAN_RESULT}[symbols][TEST_LANGUAGE][options]
  Should Be True  'hi' in $languages or 'ne' in $languages
  Do Not Expect Symbol  R_MIXED_CHARSET

Names with diacritics in a long English text are not a sign
  Scan File  ${RSPAMD_TESTDIR}/messages/chartable_english_names.eml
  ...  Settings=${SETTINGS_CHARTABLE}
  Expect Symbol With Option  TEST_LANGUAGE  en
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

Cyrillic first mixed script is detected
  Scan File  ${RSPAMD_TESTDIR}/messages/chartable_cyrillic_first.eml
  ...  Settings=${SETTINGS_CHARTABLE}
  Expect Symbol  R_MIXED_CHARSET
  Expect Symbol With Option  TEST_CHARTABLE_WORDS  аpple:mixed_script

Long mixed script word is not exempt
  Scan File  ${RSPAMD_TESTDIR}/messages/chartable_long_mixed.eml
  ...  Settings=${SETTINGS_CHARTABLE}
  Expect Symbol  R_MIXED_CHARSET
  Expect Symbol With Option  TEST_CHARTABLE_WORDS  yourаccountsuspended:mixed_script

Whole word homograph is retained
  Scan File  ${RSPAMD_TESTDIR}/messages/chartable_whole_word.eml
  ...  Settings=${SETTINGS_CHARTABLE}
  Expect Symbol With Option  TEST_CHARTABLE_WORDS  раура:confusable_candidate
  Do Not Expect Symbol With Option  TEST_CHARTABLE_WORDS  раура:unicode_spoof
  Do Not Expect Symbol  R_MIXED_CHARSET

Unicode URL homograph is detected
  Scan File  ${RSPAMD_TESTDIR}/messages/chartable_url_homograph.eml
  ...  Settings=${SETTINGS_CHARTABLE}
  Expect Symbol  R_MIXED_CHARSET_URL

Legitimate non-Latin URL is not penalised
  Scan File  ${RSPAMD_TESTDIR}/messages/chartable_url_legitimate.eml
  ...  Settings=${SETTINGS_CHARTABLE}
  Do Not Expect Symbol  R_MIXED_CHARSET_URL

Digits and connectors do not hide script mixing
  Scan File  ${RSPAMD_TESTDIR}/messages/chartable_script_separators.eml
  ...  Settings=${SETTINGS_CHARTABLE}
  Expect Symbol  R_MIXED_CHARSET
  Expect Symbol With Option  TEST_CHARTABLE_WORDS  а1pple:mixed_script
  Expect Symbol With Option  TEST_CHARTABLE_WORDS  а_pple:mixed_script

Long words do not hide repeated combining marks
  Scan File  ${RSPAMD_TESTDIR}/messages/chartable_repeated_marks.eml
  ...  Settings=${SETTINGS_CHARTABLE}
  Expect Symbol  R_MIXED_CHARSET
  Expect Symbol With Option  TEST_CHARTABLE_WORDS  ä̈bcdefghijklm:invisible
  Do Not Expect Symbol With Option  TEST_CHARTABLE_WORDS  ä̈bcdefghijklm:mixed_script

Normalisation does not hide mixed number sets
  Scan File  ${RSPAMD_TESTDIR}/messages/chartable_mixed_numbers.eml
  ...  Settings=${SETTINGS_CHARTABLE}
  Expect Symbol  R_MIXED_CHARSET
  Expect Symbol With Option  TEST_CHARTABLE_WORDS  abc11xyz:mixed_numbers
  Expect Symbol With Option  TEST_CHARTABLE_WORDS  1١:mixed_numbers
  Do Not Expect Symbol With Option  TEST_CHARTABLE_WORDS  abc11xyz:mixed_script
  Do Not Expect Symbol With Option  TEST_CHARTABLE_WORDS  1١:mixed_script

Ordinary Cyrillic skeleton candidates are not penalised
  Scan File  ${RSPAMD_TESTDIR}/messages/chartable_sugar.eml
  ...  Settings=${SETTINGS_CHARTABLE}
  Expect Symbol With Option  TEST_CHARTABLE_WORDS  сахар:confusable_candidate
  Do Not Expect Symbol  R_MIXED_CHARSET
  Do Not Expect Symbol  R_MIXED_CHARSET_URL

Standalone whole-script URL needs corroborating evidence
  Scan File  ${RSPAMD_TESTDIR}/messages/chartable_url_whole_script.eml
  ...  Settings=${SETTINGS_CHARTABLE}
  Do Not Expect Symbol  R_MIXED_CHARSET_URL

Mixed-script URL is detected without displayed URL
  Scan File  ${RSPAMD_TESTDIR}/messages/chartable_url_mixed_script.eml
  ...  Settings=${SETTINGS_CHARTABLE}
  Expect Symbol  R_MIXED_CHARSET_URL

Legitimate combining marks and number sets stay clean
  Scan File  ${RSPAMD_TESTDIR}/messages/chartable_clean_unicode.eml
  ...  Settings=${SETTINGS_CHARTABLE}
  Do Not Expect Symbol  R_MIXED_CHARSET
  Do Not Expect Symbol  TEST_CHARTABLE_WORDS

Mixed script words are seen in a long text
  [Documentation]  Three words of mixed scripts among a hundred plain ones
  Scan File  ${RSPAMD_TESTDIR}/messages/chartable_diluted_mixed.eml
  ...  Settings=${SETTINGS_CHARTABLE}
  Expect Symbol  R_MIXED_CHARSET

One mixed script word in a long text is not enough
  Scan File  ${RSPAMD_TESTDIR}/messages/chartable_diluted_one.eml
  ...  Settings=${SETTINGS_CHARTABLE}
  Do Not Expect Symbol  R_MIXED_CHARSET

Host in the ASCII form of an international name is checked as displayed
  Scan File  ${RSPAMD_TESTDIR}/messages/chartable_punycode_host.eml
  ...  Settings=${SETTINGS_CHARTABLE}
  Expect Symbol  R_MIXED_CHARSET_URL
