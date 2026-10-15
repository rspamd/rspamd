*** Settings ***
Suite Setup     SSL Server Suite Setup
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${GTUBE}               ${RSPAMD_TESTDIR}/messages/gtube.eml
${SETTINGS_NOSYMBOLS}  {symbols_enabled = []}

*** Test Cases ***
Controller SSL - stat
  [Documentation]  Fetch /stat over HTTPS from the controller SSL port.
  Fetch HTTPS And Expect 200  ${RSPAMD_PORT_CONTROLLER_SSL}  /stat

Controller SSL - errors
  [Documentation]  Fetch /errors over HTTPS from the controller SSL port
  Fetch HTTPS And Expect 200  ${RSPAMD_PORT_CONTROLLER_SSL}  /errors

Controller SSL - request in one TLS record larger than 8 KiB
  [Documentation]  Headers and body arrive in one TLS record that does not fit
  ...              into the 8 KiB read buffer: the remainder stays decrypted
  ...              inside OpenSSL and must be read without a socket event
  ${status} =  HTTPS Post Single Record  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER_SSL}  /ping  12000
  Should Be Equal As Integers  ${status}  200

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

Normal worker SSL - request in one TLS record larger than 8 KiB
  [Documentation]  Same as the controller case, for /checkv2 on the normal worker
  ${status} =  HTTPS Post Single Record  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL_SSL}  /checkv2  12000
  Should Be Equal As Integers  ${status}  200

Normal worker plain still works alongside SSL
  [Documentation]  Plain HTTP normal port must still work when SSL port is also configured
  Scan File  ${GTUBE}  Settings=${SETTINGS_NOSYMBOLS}
  Expect Symbol  GTUBE

*** Keywords ***
SSL Server Suite Setup
  [Documentation]  Run Rspamd's startup readiness check pings the plain
  ...              normal worker and (for configs with a control socket)
  ...              waits for the controller to register its workers with
  ...              main. Neither of those guarantees the controller's
  ...              SSL listener on PORT_CONTROLLER_SSL is already
  ...              accepting -- OpenSSL context init for that listener
  ...              can lag worker registration by hundreds of ms, and
  ...              under parallel pabot load (4 workers + concurrent
  ...              serial robot on the same box) we have observed lags
  ...              past 6s, exhausting the per-test retry budget that
  ...              previously sat in each SSL test.
  ...
  ...              Pay that wait once here, with a generous 30s budget,
  ...              so individual tests can issue a single direct HTTPS
  ...              request. If the listener never comes up the suite
  ...              setup fails loudly instead of every test retrying
  ...              independently.
  Wait Until Keyword Succeeds  60x  0.5s
  ...  Fetch HTTPS And Expect 200  ${RSPAMD_PORT_CONTROLLER_SSL}  /ping

Fetch HTTPS And Expect 200
  [Arguments]  ${port}  ${path}
  @{result} =  HTTPS  GET  ${RSPAMD_LOCAL_ADDR}  ${port}  ${path}
  Should Be Equal As Integers  ${result}[0]  200
