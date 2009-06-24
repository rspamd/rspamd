# Different headers violation

# Subject need encoding
$__SUBJECT_ENCODED_B64 = "Subject=/=\?\S+\?B\?/iX";
$__SUBJECT_ENCODED_QP="Subject=/=\?\S+\?Q\?/iX";
$__SUBJECT_NEEDS_MIME="Subject=/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\xff]/X";
$SUBJECT_NEEDS_ENCODING = "!${__SUBJECT_ENCODED_B64} & !${__SUBJECT_ENCODED_QP} & ${__SUBJECT_NEEDS_MIME}";
$__HAS_SUBJECT="header_exists(Subject)";
$__EMPTY_SUBJECT="Subject=/^$/";
$MISSING_SUBJECT="!${__HAS_SUBJECT} | ${__EMPTY_SUBJECT}";
$__R_RCVD_POCHTA_RU="Received=/by mail\d\.ks\.pochta\.ru \( sendmail 8\.\d{2}\.\d\/8\.\d{2}\.\d\) with esmtpa id/H";
$__R_MUA_OUTLOOK="X-Mailer=/^Microsoft Outlook Express/Hr";
$__R_MUA_THEBAT="X-Mailer=/^The Bat!/H";
$__R_CTYPE_TEXT="content_type_is_type(text)";
$__R_CTE_7BIT="compare_transfer_encoding(7bit)";
$__R_BODY_8BIT="/[^\x01-\x7f]/Mr";
$R_BAD_CTE_7BIT="${__R_CTYPE_TEXT} & ${__R_CTE_7BIT} & ${__R_BODY_8BIT}";
$R_TLD_TK = "/\.tk$/U";
$R_POCHTA_RU = "${__R_RCVD_POCHTA_RU} & ${R_TLD_TK} & ${SUBJECT_NEEDS_ENCODING}";
$R_TMP_SPAMMY_MAILER = "X-Mailer=/^(?:Exim 3\.12|Gentoo|Qmail 2\.67|Sendmail 3\.84\/3\.84|WebPOP 1\.0|mLogic)/H";
$R_WWW_EKONF_COM = "${__R_MEGA_TABLE} & ${__R_GREEK_SYMBOLS}";
$R_FREE_HOSTING_NAROD = "/\.narod\.ru/U";
$R_TINYURL = "/http:\/\/(?:tinyurl\.com|snipr\.com|b23\.ru)\/\w/U";
$R_FREE_HOSTING = "/\.(?:fromru\.com|front\.ru|hotbox\.ru|hotmail\.ru|krovatka\.su|land\.ru|mail15\.com|mail333\.com|newmail\.ru|nightmail\.ru|nm\.ru|pisem\.net|pochtamt\.ru|pop3\.ru|rbcmail\.ru|smtp\.ru)/U";

$__HAS_TO="header_exists(To)";
$MISSING_TO="!${__HAS_TO}";
$__UNDISC_RCPT="To=/^<?undisclosed-recipient/Hi";
$R_UNDISC_RCPT="${MISSING_TO} | ${__UNDISC_RCPT}";

$__HAS_MID="header_exists(Message-Id)";
$MISSING_MID="!${__HAS_MID}";
$R_RCVD_SPAMBOTS="Received=/^from \[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\] by [-.\w+]{5,255}; [SMTWF][a-z][a-z], [\s\d]?\d [JFMAJSOND][a-z][a-z] \d{4} \d{2}:\d{2}:\d{2} [-+]\d{4}$/mH";
$R_TO_SEEMS_AUTO="To=/\"?(?<bt>[-.\w]{1,64})\"?\s<\k<bt>\@/H";
$R_MISSING_CHARSET="content_type_is_type(text) & !content_type_has_param(charset)";
$R_SAJDING="Subject=/\bsajding(?:om|a)?\b/iH";
$__R_MUA_MPOP_WEBMAIL="X-Mailer=/^mPOP Web-Mail \d\.\d{2}$/H";
$__R_MID_MAILRU="Message-Id=/\@w+\.mail\.ru>$/H";
$__R_RCVD_FROM_MAILRU="Received=/ by [a-z\.]+\d*\.mail\.ru with /H";
$__R_X_RCVD_FROM_MAILRU="X-Received=/ by [a-z\.]+\d*\.mail\.ru with /H";
$R_FORGED_MPOP_WEBMAIL="${__R_MUA_MPOP_WEBMAIL} & !(${__R_RCVD_FROM_MAILRU} | ${__R_X_RCVD_FROM_MAILRU} | ${__R_MID_MAILRU})";
$__R_BGCOLOR="/BGCOLOR=/iM";
$__R_FONT_COLOR="/font color=[\"']?\#FFFFFF[\"']?/iM";
$R_WHITE_ON_WHITE="(!${__R_BGCOLOR} & ${__R_FONT_COLOR})";
$R_NO_SPACE_IN_FROM="From=/\S<[-\w\.]+\@[-\w\.]+>/X";
$R_FLASH_REDIR_IMGSHACK="/^(?:http:\/\/)?img\d{1,5}\.imageshack\.us\/\S+\.swf/U";
$__R_RCVD_FROM_VALUEHOST="Received=/\sb0\.valuehost\.ru/H";
$__R_CYR_PHONE="/8 \(\xD799\)/P";

$R_SPAM_FROM_VALUEHOST="${__R_RCVD_FROM_VALUEHOST} & ${__R_CYR_PHONE}";
$__HAS_USER_AGENT="header_exists(User-Agent)";
$__HAS_X_MAILER="header_exists(X-Mailer)";

$__R_RCVD_FROM_MTU="Received=/smtp\d*\.mtu\.ru/H";
$__R_MID_MTU="Message-Id=/\@smtp\d*\.mtu\.ru>$/H";

$__R_RCVD_FROM_ONO="Received=/smtp\d*\.ono\.com/H";
$__R_MID_ONO="Message-Id=/\@ono\.com>$/H";

$__R_RCVD_FROM_VERSATEL="Received=/mail\d*do\.versatel\.de/H";
$__R_MID_VERSATEL="Message-Id=/\@versanet\.de>$/H";

$__R_RCVD_FROM_LIBERO="Received=/cp-out\d+\.libero\.it/H";
$__R_MID_LIBERO="Message-Id=/[\da-f]{12}\.[\da-f]{16}@/H";

$R_SPAM_FROM_MTU="!(${__HAS_X_MAILER} | ${__HAS_USER_AGENT}) & ${__R_RCVD_FROM_MTU} & ${__R_MID_MTU}"; 
$R_SPAM_FROM_ONO="!(${__HAS_X_MAILER} | ${__HAS_USER_AGENT}) & ${__R_RCVD_FROM_ONO} & ${__R_MID_ONO}";
$R_SPAM_FROM_VERSATEL="!(${__HAS_X_MAILER} | ${__HAS_USER_AGENT}) & ${__R_RCVD_FROM_VERSATEL} & ${__R_MID_VERSATEL}";
$R_SPAM_FROM_LIBERO="!(${__HAS_X_MAILER} | ${__HAS_USER_AGENT}) & ${__R_RCVD_FROM_LIBERO} & ${__R_MID_LIBERO}";
#$R_FAKE_OUTLOOK="${__R_MUA_OUTLOOK}";
# $R_FAKE_OUTLOOK="${__R_MUA_OUTLOOK} & (${SUBJECT_NEEDS_ENCODING} | ${R_BAD_CTE_7BIT})";
$R_FAKE_OUTLOOK="${__R_MUA_OUTLOOK} & ${R_BAD_CTE_7BIT}";
$R_FAKE_THEBAT="${__R_MUA_THEBAT} & ${SUBJECT_NEEDS_ENCODING}";

$__YAHOO_BULK="Received=/from \[\S+\] by \S+\.(?:groups|scd|dcn)\.yahoo\.com with NNFMP/H";
$__ANY_OUTLOOK_MUA="X-Mailer=/^Microsoft Outlook\b/H";
$MIME_HTML_ONLY="has_only_html_part()";
$FORGED_OUTLOOK_HTML="!${__YAHOO_BULK} & ${__ANY_OUTLOOK_MUA} & ${MIME_HTML_ONLY}";
$SUSPICIOUS_RECIPS="compare_recipients_distance(0.65)";
$SORTED_RECIPS="is_recipients_sorted()";
$TRACKER_ID="/^[a-z0-9]{6,24}[-_a-z0-9]{2,36}[a-z0-9]{6,24}\s*\z/isPr";
$__FROM_ENCODED_B64="From=/\=\?\S+\?B\?/iX";
$__FROM_NEEDS_MIME="From=/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\xff]/H";
$FROM_EXCESS_BASE64="${__FROM_ENCODED_B64} & !${__FROM_NEEDS_MIME}";

$__OE_MUA="X-Mailer=/\bOutlook Express [456]\./H";
$__OE_MSGID_1="Message-Id=/^[A-Za-z0-9-]{7}[A-Za-z0-9]{20}\@hotmail\.com$/mH";
$__OE_MSGID_2="Message-Id=/^(?:[0-9a-f]{8}|[0-9a-f]{12})\$[0-9a-f]{8}\$[0-9a-f]{8}\@\S+$/mH";
$__LYRIS_EZLM_REMAILER="List-Unsubscribe=/<mailto:(?:leave-\S+|\S+-unsubscribe)\@\S+>$/H";
#$__GATED_THROUGH_RCVD_REMOVER="gated_through_received_hdr_remover()";
$__WACKY_SENDMAIL_VERSION="Received=/\/CWT\/DCE\)/H";
$__IPLANET_MESSAGING_SERVER="Received=/iPlanet Messaging Server/H";
$__HOTMAIL_BAYDAV_MSGID="Message-Id=/^BAY\d+-DAV\d+[A-Z0-9]{25}\@phx\.gbl$/mH";
$__SYMPATICO_MSGID="Message-Id=/^BAYC\d+-PASMTP\d+[A-Z0-9]{25}\@CEZ\.ICE$/mH";
# $__UNUSABLE_MSGID="${__LYRIS_EZLM_REMAILER} | ${__GATED_THROUGH_RCVD_REMOVER} | ${__WACKY_SENDMAIL_VERSION} | ${__IPLANET_MESSAGING_SERVER} | ${__HOTMAIL_BAYDAV_MSGID} | ${__SYMPATICO_MSGID}";
$__UNUSABLE_MSGID="${__LYRIS_EZLM_REMAILER} | ${__WACKY_SENDMAIL_VERSION} | ${__IPLANET_MESSAGING_SERVER} | ${__HOTMAIL_BAYDAV_MSGID} | ${__SYMPATICO_MSGID}";
$__FORGED_OE="${__OE_MUA} & !{__OE_MSGID_1 & !${__OE_MSGID_2} & !{__UNUSABLE_MSGID}";
$__OUTLOOK_DOLLARS_MUA="X-Mailer=/^Microsoft Outlook(?: 8| CWS, Build 9|, Build 10)\./H";
$__OUTLOOK_DOLLARS_OTHER="Message-Id=/^\!\~\!/mH";
$__VISTA_MSGID="Message-Id=/^[A-F\d]{32}\@\S+$/mH";
$__IMS_MSGID="Message-Id=/^[A-F\d]{36,40}\@\S+$/mH";
$__FORGED_OUTLOOK_DOLLARS="${__OUTLOOK_DOLLARS_MUA} & !${__OE_MSGID_2} & !${__OUTLOOK_DOLLARS_OTHER} & !${__VISTA_MSGID} & !${__IMS_MSGID} & !${__UNUSABLE_MSGID}";
$__FMO_EXCL_O3416="X-Mailer=/^Microsoft Outlook, Build 10.0.3416$/H";
$__FMO_EXCL_OE3790="X-Mailer=/^Microsoft Outlook Express 6.00.3790.3959$/H";
$FORGED_MUA_OUTLOOK="(${__FORGED_OE} | ${__FORGED_OUTLOOK_DOLLARS}) & !${__FMO_EXCL_O3416} & !${__FMO_EXCL_OE3790} & !${__VISTA_MSGID}";

$__SANE_MSGID="Message-Id=/^[^<>\\ \t\n\r\x0b\x80-\xff]+\@[^<>\\ \t\n\r\x0b\x80-\xff]+\s*$/mH";
$__MSGID_COMMENT="Messagr-Id=/\(.*\)/mH";
$INVALID_MSGID="${__HAS_MID} & !(${__SANE_MSGID} | ${__MSGID_COMMENT})";
$HTML_MIME_NO_HTML_TAG="${MIME_HTML_ONLY} & !${__TAG_EXISTS_HTML}";
$__CD="header_exists(Content-Disposition)";
$__CTE="header_exists(Content-Transfer-Encoding)";
$__CT="header_exists(Content-Type)";
$__MIME_VERSION="header_exists(MIME-Version)";
#$__CT_TEXT_PLAIN="Content-Type=/^text\/plain\b/iH";
$__CT_TEXT_PLAIN="content_type_is_type(text) & content_type_is_subtype(plain)";
$MIME_HEADER_CTYPE_ONLY="!${__CD} & !${__CTE} & ${__CT} & !${__MIME_VERSION} & !${__CT_TEXT_PLAIN}";

$__HAS_MSMAIL_PRI="header_exists(X-MSMail-Priority)";
$__HAS_MIMEOLE="header_exists(X-MimeOLE)";
$__HAS_SQUIRRELMAIL_IN_MAILER="X-Mailer=/SquirrelMail\b/H";
$MISSING_MIMEOLE="${__HAS_MSMAIL_PRI} & !${__HAS_MIMEOLE} & !${__HAS_SQUIRRELMAIL_IN_MAILER}";
$__MSGID_DOLLARS_OK="Message-Id=/[0-9a-f]{4,}\$[0-9a-f]{4,}\$[0-9a-f]{4,}\@\S+/Hr";
$__MIMEOLE_MS="X-MimeOLE=/^Produced By Microsoft MimeOLE/H";
$__RCVD_WITH_EXCHANGE="Received=/with Microsoft Exchange Server/H";
$RATWARE_MS_HASH="${__MSGID_DOLLARS_OK} & !${__MIMEOLE_MS} & !${__RCVD_WITH_EXCHANGE}";
$STOX_REPLY_TYPE="Content-Type=/text\/plain; .* reply-type=original/H";
$__FHELO_VERIZON="X-Spam-Relays-Untrusted=/^[^\]]+ helo=[^ ]+verizon\.net /iH";
$__FHOST_VERIZON="X-Spam-Relays-Untrusted=/^[^\]]+ rdns=[^ ]+verizon\.net /iH";
$FM_FAKE_HELO_VERIZON="${__FHELO_VERIZON} & !${__FHOST_VERIZON}";
$__AT_YAHOO_MSGID="Message-Id=/\@yahoo\.com\b/iH";
$__FROM_YAHOO_COM="From=/\@yahoo\.com\b/iH";
$FORGED_MSGID_YAHOO="${__AT_YAHOO_MSGID} & !${__FROM_YAHOO_COM}";

$__THEBAT_MUA_V1="X-Mailer=/^The Bat! \(v1\./H";
$__CTYPE_HAS_BOUNDARY="Content-Type=/boundary/iH";
$__BAT_BOUNDARY="Content-Type=/boundary=\"?-{10}/H";
$__MAILMAN_21="X-Mailman-Version=/\d/H";
$__DOUBLE_IP_SPAM_1="Received=/from \[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\] by \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} with/H";
$__DOUBLE_IP_SPAM_2="Received=/from\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+by\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3};/H";
$FORGED_MUA_THEBAT_BOUN="${__THEBAT_MUA_V1} & ${__CTYPE_HAS_BOUNDARY} & !${__BAT_BOUNDARY} & !${__MAILMAN_21}";
$RCVD_DOUBLE_IP_SPAM="${__DOUBLE_IP_SPAM_1} | ${__DOUBLE_IP_SPAM_2}";

$__REPTO_QUOTE="Reply-To=/\".*\"\s*\</H";
$__FROM_YAHOO_COM="From=/\@yahoo\.com\b/iH";
$__AT_YAHOO_MSGID="Message-Id=/\@yahoo\.com\b/iH";
$REPTO_QUOTE_YAHOO="${__REPTO_QUOTE} & (${__FROM_YAHOO_COM} | ${__AT_YAHOO_MSGID})";


$__XM_GNUS="X-Mailer=/^Gnus v/H";
$__XM_MSOE5="X-Mailer=/^Microsoft Outlook Express 5/H";
$__XM_MSOE6="X-Mailer =~ /^Microsoft Outlook Express 6/H";
$__XM_MOZ4="X-Mailer=/^Mozilla 4/H";
$__XM_SKYRI="X-Mailer=/^SKYRiXgreen/H";
$__XM_WWWMAIL="X-Mailer=/^WWW-Mail \d/H";
$__UA_GNUS="User-Agent=/^Gnus/H";
$__UA_KNODE="User-Agent=/^KNode/H";
$__UA_MUTT="User-Agent=/^Mutt/H";
$__UA_PAN="User-Agent=/^Pan/H";
$__UA_XNEWS="User-Agent=/^Xnews/H";
$__NO_INR_YES_REF="${__XM_GNUS} | ${__XM_MSOE5} | ${__XM_MSOE6} | ${__XM_MOZ4} | ${__XM_SKYRI} | ${__XM_WWWMAIL} | ${__UA_GNUS} | ${__UA_KNODE} | ${__UA_MUTT} | ${__UA_PAN} | ${__UA_XNEWS}";

$__SUBJ_RE="Subject=/^R[eE]:/H";
$__HAS_REF="header_exists(References)";
$__MISSING_REF="!${__HAS_REF}";
$FAKE_REPLY_C="${__SUBJ_RE} & ${__MISSING_REF} & ${__NO_INR_YES_REF}";

