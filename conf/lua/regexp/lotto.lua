-- Rules that are specific for lotto spam messages

local reconf = config['regexp']

local r_lotto_from = 'From=/(?:lottery|News center|congratulation to you|NED INFO|BRITISH NATIONAL HEADQUATERS|MICROSOFT ON LINE SUPPORT TEAM|prize|online notification)/iH'
local r_lotto_subject = 'Subject=/(?:\\xA3\\d|pounds?|FINAL NOTIFICATION|FOR YOUR ATTENTION|File in Your Claims?|ATTN|prize|Claims requirement|amount|confirm|your e-mail address won|congratulations)/iH'
local r_lotto_body = '/(?:won|winning|\\xA3\\d|pounds?|GBP|LOTTERY|awards|prize)/isrP'
local kam_lotto1 = '/(e-?mail address (have emerged a winner|has won|attached to (ticket|reference)|was one of the ten winners)|random selection in our computerized email selection system)/isrP'
local kam_lotto2 = '/((ticket|serial|lucky) number|secret pin ?code|batch number|reference number|promotion date)/isrP'
local kam_lotto3 = '/(won|claim|cash prize|pounds? sterling)/isrP'
local kam_lotto4 = '/(claims (officer|agent)|lottery coordinator|fiduciary (officer|agent)|fiduaciary claims)/isrP'
local kam_lotto5 = '/(freelotto group|Royal Heritage Lottery|UK National (Online)? Lottery|U\\.?K\\.? Grand Promotions|Lottery Department UK|Euromillion Loteria|Luckyday International Lottery|International Lottery)/isrP'
local kam_lotto6 = '/(Dear Lucky Winner|Winning Notification|Attention:Winner|Dear Winner)/isrP'
local kam_lotto7 = 'Subject=/(Your Lucky Day|(Attention:|ONLINE) WINNER)/iH'
reconf['R_LOTTO'] = string.format('((%s) | (%s) | (%s)) & regexp_match_number(3, (%s), (%s), (%s), (%s),  (%s), (%s), (%s), (%s), (%s))', reconf['R_UNDISC_RCPT'], reconf['R_BAD_CTE_7BIT'], reconf['R_NO_SPACE_IN_FROM'], r_lotto_from, r_lotto_subject, r_lotto_body, kam_lotto1, kam_lotto2, kam_lotto3, kam_lotto4, kam_lotto5, kam_lotto6)

