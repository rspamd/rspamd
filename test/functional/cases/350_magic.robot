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
  Scan File  ${TESTDIR}/messages/gargantua.eml
  Expect Symbol  MAGIC_SYM_ZIP_2
  Expect Symbol  MAGIC_SYM_RAR_3
  Expect Symbol  MAGIC_SYM_EXE_4
  Expect Symbol  MAGIC_SYM_ELF_5
  Expect Symbol  MAGIC_SYM_LNK_6
  Expect Symbol  MAGIC_SYM_CLASS_7
  Expect Symbol  MAGIC_SYM_RTF_8
  Expect Symbol  MAGIC_SYM_PDF_9
  Expect Symbol  MAGIC_SYM_PS_10
  Expect Symbol  MAGIC_SYM_CHM_11
  Expect Symbol  MAGIC_SYM_DJVU_12
  Expect Symbol  MAGIC_SYM_ARJ_13
  Expect Symbol  MAGIC_SYM_CAB_14
  Expect Symbol  MAGIC_SYM_ACE_15
  Expect Symbol  MAGIC_SYM_TAR_16
  Expect Symbol  MAGIC_SYM_BZ2_17
  Expect Symbol  MAGIC_SYM_XZ_18
  Expect Symbol  MAGIC_SYM_LZ4_19
  Expect Symbol  MAGIC_SYM_ZST_20
  Expect Symbol  MAGIC_SYM_DMG_21
  Expect Symbol  MAGIC_SYM_ISO_22
  Expect Symbol  MAGIC_SYM_ZOO_23
  Expect Symbol  MAGIC_SYM_EPUB_24
  Expect Symbol  MAGIC_SYM_XAR_25
  Expect Symbol  MAGIC_SYM_PSD_26
  Expect Symbol  MAGIC_SYM_PCX_27
  Expect Symbol  MAGIC_SYM_TIFF_28
  Expect Symbol  MAGIC_SYM_ICO_29
  Expect Symbol  MAGIC_SYM_SWF_30
  Expect Symbol  MAGIC_SYM_DOC_31
  Expect Symbol  MAGIC_SYM_XLS_32
  Expect Symbol  MAGIC_SYM_PPT_33
  Expect Symbol  MAGIC_SYM_MSI_34
  Expect Symbol  MAGIC_SYM_MSG_35
  Expect Symbol  MAGIC_SYM_DOCX_36
  Expect Symbol  MAGIC_SYM_XLSX_37
  Expect Symbol  MAGIC_SYM_PPTX_38
  Expect Symbol  MAGIC_SYM_ODT_39
  Expect Symbol  MAGIC_SYM_ODS_40
  Expect Symbol  MAGIC_SYM_ODP_41
  Expect Symbol  MAGIC_SYM_7Z_42
  Expect Symbol  MAGIC_SYM_VSD_43
  Expect Symbol  MAGIC_SYM_PNG_44
  Expect Symbol  MAGIC_SYM_JPG_45
  Expect Symbol  MAGIC_SYM_GIF_46
  Expect Symbol  MAGIC_SYM_BMP_47
  Expect Symbol  MAGIC_SYM_TXT_48
  Expect Symbol  MAGIC_SYM_HTML_49
  Expect Symbol  MAGIC_SYM_CSV_50
  Expect Symbol  MAGIC_SYM_DWG_51
  Expect Symbol  MAGIC_SYM_JAR_52
  Expect Symbol  MAGIC_SYM_APK_53
  Expect Symbol  MAGIC_SYM_BAT_54
  Expect Symbol  MAGIC_SYM_ICS_55
  Expect Symbol  MAGIC_SYM_VCF_56

