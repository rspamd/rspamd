*** Settings ***
Documentation    Dynamic configuration is disabled (`enabled = false`) while the deprecated dynamic_conf module has
...              Redis servers: its Redis data is not applied, and the module says that the backend alone is not
...              enough, dynconf has to be enabled as well.
Suite Setup      Rspamd Setup
Suite Teardown   Rspamd Teardown
Library          Process
Library          OperatingSystem
Library          ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource         ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables        ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}               ${RSPAMD_TESTDIR}/configs/dynconf_disabled.conf
${RSPAMD_SCOPE}         Suite
${RSPAMD_URL_TLD}       ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${MESSAGE}              ${RSPAMD_TESTDIR}/messages/dynconf_hello.eml

*** Test Cases ***
The deprecated module says that dynconf is disabled
  ${log} =  Get File  ${RSPAMD_TMPDIR}/rspamd.log
  Should Match Regexp  ${log}  \\[error\\][^\\n]*its redis data is NOT applied: dynconf is disabled
  Should Contain  ${log}  Enable dynconf and set `dynconf { backend = "redis"; }` to apply it
  Should Not Contain  ${log}  the dynconf backend is

The static configuration is served
  Scan File  ${MESSAGE}
  Expect Symbol With Score  DYN_HELLO  2.0
  Expect Required Score  100

The write endpoints say that dynconf is disabled
  ${result} =  HTTP  POST  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /saveactions  [200, null, 60, null]
  Should Be Equal As Integers  ${result}[0]  503
