*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Test Cases ***
Metrics Default Content Type
  [Documentation]  Without Accept header, should return OpenMetrics format
  @{result} =  HTTP With Headers  GET  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /metrics
  Should Be Equal As Integers  ${result}[0]  200
  Should Contain  ${result}[2][Content-Type]  application/openmetrics-text
  Should Contain  ${result}[1].decode('utf-8')  \# EOF

Metrics With OpenMetrics Accept
  [Documentation]  With Accept: application/openmetrics-text, should return OpenMetrics
  &{headers} =  Create Dictionary  Accept=application/openmetrics-text
  @{result} =  HTTP With Headers  GET  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /metrics  headers=${headers}
  Should Be Equal As Integers  ${result}[0]  200
  Should Contain  ${result}[2][Content-Type]  application/openmetrics-text
  Should Contain  ${result}[1].decode('utf-8')  \# EOF

Metrics With Text Plain Accept
  [Documentation]  With Accept: text/plain, should return Prometheus 0.0.4 format
  &{headers} =  Create Dictionary  Accept=text/plain
  @{result} =  HTTP With Headers  GET  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /metrics  headers=${headers}
  Should Be Equal As Integers  ${result}[0]  200
  Should Contain  ${result}[2][Content-Type]  text/plain
  Should Contain  ${result}[1].decode('utf-8')  \# EOF

Metrics With Wildcard Accept
  [Documentation]  With Accept: */*, should return default (OpenMetrics)
  &{headers} =  Create Dictionary  Accept=*/*
  @{result} =  HTTP With Headers  GET  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /metrics  headers=${headers}
  Should Be Equal As Integers  ${result}[0]  200
  Should Contain  ${result}[2][Content-Type]  application/openmetrics-text

Metrics With Quality Factor
  [Documentation]  Accept header with quality factors should prefer higher quality
  &{headers} =  Create Dictionary  Accept=text/plain;q=0.9, application/openmetrics-text;q=1.0
  @{result} =  HTTP With Headers  GET  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /metrics  headers=${headers}
  Should Be Equal As Integers  ${result}[0]  200
  Should Contain  ${result}[2][Content-Type]  application/openmetrics-text

Metrics Fallback For Unknown Accept
  [Documentation]  With unsupported Accept type, should fallback to text/plain
  &{headers} =  Create Dictionary  Accept=application/xml
  @{result} =  HTTP With Headers  GET  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /metrics  headers=${headers}
  Should Be Equal As Integers  ${result}[0]  200
  Should Contain  ${result}[2][Content-Type]  text/plain

Stat With Msgpack Accept
  [Documentation]  With Accept: application/msgpack, should return msgpack format
  &{headers} =  Create Dictionary  Accept=application/msgpack
  @{result} =  HTTP With Headers  GET  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /stat  headers=${headers}
  Should Be Equal As Integers  ${result}[0]  200
  Should Contain  ${result}[2][Content-Type]  application/msgpack

Stat With JSON Accept
  [Documentation]  With Accept: application/json, should return JSON format
  &{headers} =  Create Dictionary  Accept=application/json
  @{result} =  HTTP With Headers  GET  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /stat  headers=${headers}
  Should Be Equal As Integers  ${result}[0]  200
  Should Contain  ${result}[2][Content-Type]  application/json

Stat With Zstd Encoding
  [Documentation]  With Accept-Encoding: zstd, should return zstd compressed response
  &{headers} =  Create Dictionary  Accept-Encoding=zstd
  @{result} =  HTTP With Headers  GET  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /stat  headers=${headers}
  Should Be Equal As Integers  ${result}[0]  200
  Should Contain  ${result}[2][Content-Encoding]  zstd

Stat With Gzip Encoding
  [Documentation]  With Accept-Encoding: gzip, should return gzip compressed response
  &{headers} =  Create Dictionary  Accept-Encoding=gzip
  @{result} =  HTTP With Headers  GET  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /stat  headers=${headers}
  Should Be Equal As Integers  ${result}[0]  200
  Should Contain  ${result}[2][Content-Encoding]  gzip

Stat With Msgpack And Zstd
  [Documentation]  With Accept: msgpack and Accept-Encoding: zstd, should return compressed msgpack
  &{headers} =  Create Dictionary  Accept=application/msgpack  Accept-Encoding=zstd
  @{result} =  HTTP With Headers  GET  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /stat  headers=${headers}
  Should Be Equal As Integers  ${result}[0]  200
  Should Contain  ${result}[2][Content-Type]  application/msgpack
  Should Contain  ${result}[2][Content-Encoding]  zstd
