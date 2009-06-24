# HTML related rules

$__MIME_HTML="content_type_is_type(text) & content_type_is_subtype(/.?html/)";
$__TAG_EXISTS_HTML="/<html/iPr";
$__TAG_EXISTS_HEAD="/<head>/iPr";
$__TAG_EXISTS_META="/<meta /iPr";
$__TAG_EXISTS_BODY="/<body/iPr";
$FORGED_OUTLOOK_TAGS="!${__YAHOO_BULK} & ${__ANY_OUTLOOK_MUA} & ${__MIME_HTML} & !(${__TAG_EXISTS_HTML} & ${__TAG_EXISTS_HEAD} & ${__TAG_EXISTS_META} & ${__TAG_EXISTS_BODY})";
$__HTML_LENGTH_1024_1536="has_content_part_len('text', 'html', 1024, 1536)";
$__HTML_LINK_IMAGE="/<img /iPr";
$HTML_SHORT_LINK_IMG_2="${__HTML_LENGTH_1024_1536} & ${__HTML_LINK_IMAGE}";

$__R_BGCOLOR="/BGCOLOR=/iM";
$__R_FONT_COLOR="/font color=[\"']?\#FFFFFF[\"']?/iM";
$R_WHITE_ON_WHITE="(!${__R_BGCOLOR} & ${__R_FONT_COLOR})";
$R_NO_SPACE_IN_FROM="From=/\S<[-\w\.]+\@[-\w\.]+>/X";
$R_FLASH_REDIR_IMGSHACK="/^(?:http:\/\/)?img\d{1,5}\.imageshack\.us\/\S+\.swf/U";
$__R_RCVD_FROM_VALUEHOST="Received=/\sb0\.valuehost\.ru/H";
$__R_CYR_PHONE="/8 \(\xD799\)/P";

$R_SPAM_FROM_VALUEHOST="${__R_RCVD_FROM_VALUEHOST} & ${__R_CYR_PHONE}";

$__R_MEGA_TABLE = "/<table border=\"0\" width=\"1\" height=\"30\">\n\s+?<tr>\n\s+?<td bgcolor=\"\#000000\"><\/td>\n\s+?<td><\/td>\n\s+?<td bgcolor=\"\#000000\"><\/td>\n\s+?<td><\/td>\n\s+?<td bgcolor=\"\#000000\"><\/td>\n\s+?<td><\/td>\n\s+?<td bgcolor=\"\#000000\"><\/td>\n\s+?<td><\/td>\n\s+?<td bgcolor=\"\#000000\"><\/td>\n\s+?<td><\/td>\n\s+?<td bgcolor=\"\#000000\"><\/td>\n\s+?<td><\/td>\n\s+?<td><\/td>\n\s+?<td><\/td>/Ps";
$__R_GREEK_SYMBOLS = "/&\#(?:1293|261|1218|1197|1245|1187|1116|569|1117|267|1179|593|1008|1247|311||311|491)/P";

$MIME_HTML_ONLY="has_only_html_part()";
$FORGED_OUTLOOK_HTML="!${__YAHOO_BULK} & ${__ANY_OUTLOOK_MUA} & ${MIME_HTML_ONLY}";

