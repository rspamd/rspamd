*** Settings ***
Library         Process

*** Test Cases ***
Lua Check
  ${result} =  Run Process  luacheck  -q  --no-color  .  cwd=${TOPDIR}
  Run Keyword If  ${result.rc} != 0  Log  ${result.stdout}
  Should Be Equal As Integers  ${result.rc}  0  msg=${result.stdout}  values=false
