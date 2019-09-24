*** Settings ***
Suite Setup     Generic Setup
Suite Teardown  Simple Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/lua_script.conf
${LUA_SCRIPT}   ${TESTDIR}/lua/magic.lua
${RSPAMD_SCOPE}  Suite
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
Magic detections bundle 1
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/gargantua.eml
  Follow Rspamd Log
  Should Contain  ${result.stdout}  MAGIC_SYM_ZIP_2
  Should Contain  ${result.stdout}  MAGIC_SYM_RAR_3
  Should Contain  ${result.stdout}  MAGIC_SYM_EXE_4
  Should Contain  ${result.stdout}  MAGIC_SYM_ELF_5
  Should Contain  ${result.stdout}  MAGIC_SYM_LNK_6
  Should Contain  ${result.stdout}  MAGIC_SYM_CLASS_7
  Should Contain  ${result.stdout}  MAGIC_SYM_RTF_8
  Should Contain  ${result.stdout}  MAGIC_SYM_PDF_9
  Should Contain  ${result.stdout}  MAGIC_SYM_PS_10
  Should Contain  ${result.stdout}  MAGIC_SYM_CHM_11
  Should Contain  ${result.stdout}  MAGIC_SYM_DJVU_12
  Should Contain  ${result.stdout}  MAGIC_SYM_ARJ_13
  Should Contain  ${result.stdout}  MAGIC_SYM_CAB_14
  Should Contain  ${result.stdout}  MAGIC_SYM_ACE_15
  Should Contain  ${result.stdout}  MAGIC_SYM_TAR_16
  Should Contain  ${result.stdout}  MAGIC_SYM_BZ2_17
  Should Contain  ${result.stdout}  MAGIC_SYM_XZ_18
  Should Contain  ${result.stdout}  MAGIC_SYM_LZ4_19
  Should Contain  ${result.stdout}  MAGIC_SYM_ZST_20
  Should Contain  ${result.stdout}  MAGIC_SYM_DMG_21
  Should Contain  ${result.stdout}  MAGIC_SYM_ISO_22
  Should Contain  ${result.stdout}  MAGIC_SYM_ZOO_23
  Should Contain  ${result.stdout}  MAGIC_SYM_EPUB_24
  Should Contain  ${result.stdout}  MAGIC_SYM_XAR_25
  Should Contain  ${result.stdout}  MAGIC_SYM_PSD_26
  Should Contain  ${result.stdout}  MAGIC_SYM_PCX_27
  Should Contain  ${result.stdout}  MAGIC_SYM_TIFF_28
  Should Contain  ${result.stdout}  MAGIC_SYM_ICO_29
  Should Contain  ${result.stdout}  MAGIC_SYM_SWF_30
  Should Contain  ${result.stdout}  MAGIC_SYM_DOC_31
  Should Contain  ${result.stdout}  MAGIC_SYM_XLS_32
  Should Contain  ${result.stdout}  MAGIC_SYM_PPT_33
  Should Contain  ${result.stdout}  MAGIC_SYM_MSI_34
  Should Contain  ${result.stdout}  MAGIC_SYM_MSG_35
  Should Contain  ${result.stdout}  MAGIC_SYM_DOCX_36
  Should Contain  ${result.stdout}  MAGIC_SYM_XLSX_37
  Should Contain  ${result.stdout}  MAGIC_SYM_PPTX_38
  Should Contain  ${result.stdout}  MAGIC_SYM_ODT_39
  Should Contain  ${result.stdout}  MAGIC_SYM_ODS_40
  Should Contain  ${result.stdout}  MAGIC_SYM_ODP_41
  Should Contain  ${result.stdout}  MAGIC_SYM_7Z_42
  Should Contain  ${result.stdout}  MAGIC_SYM_VSD_43
  Should Contain  ${result.stdout}  MAGIC_SYM_PNG_44
  Should Contain  ${result.stdout}  MAGIC_SYM_JPG_45
  Should Contain  ${result.stdout}  MAGIC_SYM_GIF_46
  Should Contain  ${result.stdout}  MAGIC_SYM_BMP_47
  Should Contain  ${result.stdout}  MAGIC_SYM_TXT_48
  Should Contain  ${result.stdout}  MAGIC_SYM_HTML_49
  Should Contain  ${result.stdout}  MAGIC_SYM_CSV_50
  Should Contain  ${result.stdout}  MAGIC_SYM_DWG_51
  Should Contain  ${result.stdout}  MAGIC_SYM_JAR_52
  Should Contain  ${result.stdout}  MAGIC_SYM_APK_53
  Should Contain  ${result.stdout}  MAGIC_SYM_BAT_54

