*** Settings ***
Library         Process

*** Test Cases ***
Lua Check
  ${result} =  Run Process  luacheck  -q  --no-color  .  cwd=${TOPDIR}
  IF  ${result.rc} != 0
    Log  ${result.stdout}
  END
  Should Be Equal As Integers  ${result.rc}  0  msg=${result.stdout}  values=false
