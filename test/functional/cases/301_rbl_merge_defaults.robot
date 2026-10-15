*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/rbl_merge_defaults.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/btc.eml
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
# default_merge_checks = false, and the rule sets ignore_defaults without merge_checks:
# one option and one score shot per check, as before request merging
GLOBAL OPT-OUT REACHES IGNORE_DEFAULTS RULES
  Scan File  ${MESSAGE}  Settings={symbols_enabled = [RBL_NOMERGE_DEFAULT]}
  Expect Symbol With Exact Options  RBL_NOMERGE_DEFAULT  example.org:first  example.org:second
  Expect Symbol With Score  RBL_NOMERGE_DEFAULT  2.0

# A rule that sets merge_checks itself is not overridden by the global default
RULE MERGE_CHECKS OVERRIDES GLOBAL DEFAULT
  Scan File  ${MESSAGE}  Settings={symbols_enabled = [RBL_MERGE_EXPLICIT]}
  Expect Symbol With Exact Options  RBL_MERGE_EXPLICIT  example.org:first,second
  Expect Symbol With Score  RBL_MERGE_EXPLICIT  1.0
