*** Settings ***
Library         Process

*** Test Cases ***
Customer Keys Override Bans And Blocked Traffic Remains Observable
  ${python} =  Evaluate  sys.executable  modules=sys
  ${result} =  Run Process  ${python}  ${RSPAMD_TESTDIR}/util/fuzzy_key_policy.py
  ...  --rspamd  ${RSPAMD}  --rspamadm  ${RSPAMADM}  -v
  ...  timeout=60s  on_timeout=kill
  Should Be Equal As Integers  ${result.rc}  0  ${result.stdout}\n${result.stderr}
