*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${SETTINGS_MAGIC}    {symbols_enabled = [MAGIC_SYM]}

*** Test Cases ***
Magic detections bundle 1
  Scan File  ${RSPAMD_TESTDIR}/messages/gargantua.eml  Settings=${SETTINGS_MAGIC}
  Expect Symbols  MAGIC_SYM_ZIP_2
  ...  MAGIC_SYM_RAR_3
  ...  MAGIC_SYM_EXE_4
  ...  MAGIC_SYM_ELF_5
  ...  MAGIC_SYM_LNK_6
  ...  MAGIC_SYM_CLASS_7
  ...  MAGIC_SYM_RTF_8
  ...  MAGIC_SYM_PDF_9
  ...  MAGIC_SYM_PS_10
  ...  MAGIC_SYM_CHM_11
  ...  MAGIC_SYM_DJVU_12
  ...  MAGIC_SYM_ARJ_13
  ...  MAGIC_SYM_CAB_14
  ...  MAGIC_SYM_ACE_15
  ...  MAGIC_SYM_TAR_16
  ...  MAGIC_SYM_BZ2_17
  ...  MAGIC_SYM_XZ_18
  ...  MAGIC_SYM_LZ4_19
  ...  MAGIC_SYM_ZST_20
  ...  MAGIC_SYM_DMG_21
  ...  MAGIC_SYM_ISO_22
  ...  MAGIC_SYM_ZOO_23
  ...  MAGIC_SYM_EPUB_24
  ...  MAGIC_SYM_XAR_25
  ...  MAGIC_SYM_PSD_26
  ...  MAGIC_SYM_PCX_27
  ...  MAGIC_SYM_TIFF_28
  ...  MAGIC_SYM_ICO_29
  ...  MAGIC_SYM_SWF_30
  ...  MAGIC_SYM_DOC_31
  ...  MAGIC_SYM_XLS_32
  ...  MAGIC_SYM_PPT_33
  ...  MAGIC_SYM_MSI_34
  ...  MAGIC_SYM_MSG_35
  ...  MAGIC_SYM_DOCX_36
  ...  MAGIC_SYM_XLSX_37
  ...  MAGIC_SYM_PPTX_38
  ...  MAGIC_SYM_ODT_39
  ...  MAGIC_SYM_ODS_40
  ...  MAGIC_SYM_ODP_41
  ...  MAGIC_SYM_7Z_42
  ...  MAGIC_SYM_VSD_43
  ...  MAGIC_SYM_PNG_44
  ...  MAGIC_SYM_JPG_45
  ...  MAGIC_SYM_GIF_46
  ...  MAGIC_SYM_BMP_47
  ...  MAGIC_SYM_TXT_48
  ...  MAGIC_SYM_HTML_49
  ...  MAGIC_SYM_CSV_50
  ...  MAGIC_SYM_DWG_51
  ...  MAGIC_SYM_JAR_52
  ...  MAGIC_SYM_APK_53
  ...  MAGIC_SYM_BAT_54
  ...  MAGIC_SYM_ICS_55
  ...  MAGIC_SYM_VCF_56
