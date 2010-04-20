-- This is main lua config file for rspamd

config['regexp'] = {}

dofile('regexp/headers.lua')
dofile('regexp/lotto.lua')
dofile('regexp/fraud.lua')
dofile('regexp/drugs.lua')

local reconf = config['regexp']

-- Uncategorized rules

local html_length_1024_1536 = 'has_content_part_len(\'text\', \'html\', 1024, 1536)'
local html_link_image = '/<img /iPr'
reconf['HTML_SHORT_LINK_IMG_2'] = string.format('(%s) & (%s)', html_length_1024_1536, html_link_image)

-- Local rules
local r_bgcolor = '/BGCOLOR=/iM'
local r_font_color = '/font color=[\\"\']?\\#FFFFFF[\\"\']?/iM'
reconf['R_WHITE_ON_WHITE'] = string.format('(!(%s) & (%s))', r_bgcolor, r_font_color)
reconf['R_FLASH_REDIR_IMGSHACK'] = '/^(?:http:\\/\\/)?img\\d{1,5}\\.imageshack\\.us\\/\\S+\\.swf/U'
local r_rcvd_from_valuehost = 'Received=/\\sb0\\.valuehost\\.ru/H'
local r_cyr_phone = '/8 \\(\\xD799\\)/P'
reconf['R_SPAM_FROM_VALUEHOST'] = string.format('(%s) & (%s)', r_rcvd_from_valuehost, r_cyr_phone)

