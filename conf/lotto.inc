# Rules for lottery spam


$__R_LOTTO_FROM="From=/(?:lottery|News center|congratulation to you|NED INFO|BRITISH NATIONAL HEADQUATERS|MICROSOFT ON LINE SUPPORT TEAM|prize|online notification)/iH";
$__R_LOTTO_SUBJECT="Subject=/(?:\xA3\d|pounds?|FINAL NOTIFICATION|FOR YOUR ATTENTION|File in Your Claims?|ATTN|prize|Claims requirement|amount|confirm|your e-mail address won|congratulations)/iH";
$__R_LOTTO_BODY="/(?:won|winning|\xA3\d|pounds?|GBP|LOTTERY|awards|prize)/isrP";
$__KAM_LOTTO1="/(e-?mail address (have emerged a winner|has won|attached to (ticket|reference)|was one of the ten winners)|random selection in our computerized email selection system)/isrP";
$__KAM_LOTTO2="/((ticket|serial|lucky) number|secret pin ?code|batch number|reference number|promotion date)/isrP";
$__KAM_LOTTO3="/(won|claim|cash prize|pounds? sterling)/isrP";
$__KAM_LOTTO4="/(claims (officer|agent)|lottery coordinator|fiduciary (officer|agent)|fiduaciary claims)/isrP";
$__KAM_LOTTO5="/(freelotto group|Royal Heritage Lottery|UK National (Online)? Lottery|U\.?K\.? Grand Promotions|Lottery Department UK|Euromillion Loteria|Luckyday International Lottery|International Lottery)/isrP";
$__KAM_LOTTO6="/(Dear Lucky Winner|Winning Notification|Attention:Winner|Dear Winner)/isrP";
$__KAM_LOTTO7="Subject=/(Your Lucky Day|(Attention:|ONLINE) WINNER)/iH";
$KAM_LOTTO1="(${R_UNDISC_RCPT} | ${R_BAD_CTE_7BIT} | ${R_NO_SPACE_IN_FROM}) & regexp_match_number(3, ${__KAM_LOTTO1}, ${__KAM_LOTTO2}, ${__KAM_LOTTO3}, ${__KAM_LOTTO4}, ${__KAM_LOTTO5}, ${__KAM_LOTTO6}, ${__KAM_LOTTO7})";
$R_LOTTO="(${R_UNDISC_RCPT} | ${R_BAD_CTE_7BIT} | ${R_NO_SPACE_IN_FROM}) & regexp_match_number(3, ${__KAM_LOTTO1},  ${__KAM_LOTTO2}, ${__KAM_LOTTO3}, ${__KAM_LOTTO4}, ${__KAM_LOTTO5}, ${__KAM_LOTTO6})";

