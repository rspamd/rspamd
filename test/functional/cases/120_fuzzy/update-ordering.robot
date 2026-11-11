*** Settings ***
Suite Setup     Fuzzy Update Ordering Setup
Suite Teardown  Rspamd Redis Teardown
Test Template   Verify Fuzzy Redis Updates
Resource        lib.robot

*** Test Cases ***
Delete Then Add Keeps The New Flag  delete-add
Add Then Delete Removes The Hash   add-delete
Duplicate Adds Merge Their Weights  duplicates

*** Keywords ***
Fuzzy Update Ordering Setup
  # Keep every explicitly queued group in one sync batch. The helper waits for
  # completion via the Redis version key, rather than sleeping after control.
  Set Suite Variable  ${RSPAMD_SETTINGS_FUZZY_WORKER}  sync = 1h; count_scan { enabled = false; }
  Fuzzy Setup Plain Mumhash

Verify Fuzzy Redis Updates
  [Arguments]  ${case}
  ${python} =  Evaluate  sys.executable  modules=sys
  ${result} =  Run Process  ${python}  ${RSPAMD_TESTDIR}/util/fuzzy_redis_ordering.py
  ...  --host  ${RSPAMD_LOCAL_ADDR}  --port  ${RSPAMD_PORT_FUZZY}
  ...  --redis-host  ${RSPAMD_REDIS_ADDR}  --redis-port  ${RSPAMD_REDIS_PORT}
  ...  --rspamadm  ${RSPAMADM}  --control  ${RSPAMD_TMPDIR}/rspamd.sock
  ...  --case  ${case}
  ...  timeout=60s  on_timeout=kill
  Should Be Equal As Integers  ${result.rc}  0  ${result.stdout}\n${result.stderr}
