-- Actually these regular expressions were obtained from SpamAssassin project, so they are licensed by apache license:
--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to you under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at:
-- 
--     http://www.apache.org/licenses/LICENSE-2.0
-- 
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
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
reconf['R_LOTTO'] = string.format('((%s) | (%s) | (%s)) & (((%s) + (%s) + (%s) + (%s) + (%s) + (%s) + (%s) + (%s) + (%s)) >= 3)', reconf['R_UNDISC_RCPT'], reconf['R_BAD_CTE_7BIT'], reconf['R_NO_SPACE_IN_FROM'], r_lotto_from, r_lotto_subject, r_lotto_body, kam_lotto1, kam_lotto2, kam_lotto3, kam_lotto4, kam_lotto5, kam_lotto6)

