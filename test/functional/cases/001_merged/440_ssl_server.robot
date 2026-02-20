*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${GTUBE}               ${RSPAMD_TESTDIR}/messages/gtube.eml
${SETTINGS_NOSYMBOLS}  {symbols_enabled = []}

*** Test Cases ***
Controller SSL - stat
  [Documentation]  Fetch /stat over HTTPS from the controller SSL port
  @{result} =  HTTPS  GET  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER_SSL}  /stat
  Should Be Equal As Integers  ${result}[0]  200

Controller SSL - errors
  [Documentation]  Fetch /errors over HTTPS from the controller SSL port
  @{result} =  HTTPS  GET  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER_SSL}  /errors
  Should Be Equal As Integers  ${result}[0]  200

Controller plain still works alongside SSL
  [Documentation]  Plain HTTP controller port must still work when SSL port is also configured
  @{result} =  HTTP  GET  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /stat
  Should Be Equal As Integers  ${result}[0]  200

Normal worker SSL - checkv2
  [Documentation]  Scan a message via /checkv2 over HTTPS on the normal worker SSL port
  Scan File SSL  ${GTUBE}  Settings=${SETTINGS_NOSYMBOLS}
  Expect Symbol  GTUBE

Normal worker SSL - checkv3
  [Documentation]  Scan a message via /checkv3 over HTTPS on the normal worker SSL port
  Scan File V3 SSL  ${GTUBE}  Settings=${SETTINGS_NOSYMBOLS}
  Expect Symbol  GTUBE

Normal worker plain still works alongside SSL
  [Documentation]  Plain HTTP normal port must still work when SSL port is also configured
  Scan File  ${GTUBE}  Settings=${SETTINGS_NOSYMBOLS}
  Expect Symbol  GTUBE
