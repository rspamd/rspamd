*** Settings ***
Library         Process
Library         OperatingSystem
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Variables       ${RSPAMD_TESTDIR}/lib/vars.py
Test Tags       redis  sentinel  tls
Test Timeout    3 minutes

*** Test Cases ***
Independent Sentinel TLS And Primary Failover
  ${python} =  Evaluate  sys.executable  modules=sys
  ${result} =  Run Process  ${python}  ${RSPAMD_TESTDIR}/util/redis_sentinel_tls.py
  ...  --rspamd  ${RSPAMD}  --rspamadm  ${RSPAMADM}  --source  ${TOPDIR}
  ...  timeout=170s  on_timeout=kill
  Log  ${result.stdout}
  Skip If  ${result.rc} == 77  ${result.stdout}
  Should Be Equal As Integers  ${result.rc}  0  ${result.stdout}\n${result.stderr}
