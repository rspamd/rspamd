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
local r_bgcolor = '/BGCOLOR=/iP'
local r_font_color = '/font color=[\\"\']?\\#FFFFFF[\\"\']?/iP'
reconf['R_WHITE_ON_WHITE'] = string.format('(!(%s) & (%s))', r_bgcolor, r_font_color)
reconf['R_FLASH_REDIR_IMGSHACK'] = '/^(?:http:\\/\\/)?img\\d{1,5}\\.imageshack\\.us\\/\\S+\\.swf/U'

-- Different text parts
reconf['R_PARTS_DIFFER'] = 'compare_parts_distance(50)';

rspamd_config.R_EMPTY_IMAGE = function (task)
	parts = task:get_text_parts()
	if parts then
		for _,part in ipairs(parts) do
			if part:is_empty() then
				images = task:get_images()
				if images then
					return true
				end
				return false
			end
		end
	end
	return false
end

-- Date issues
rspamd_config.DATE_IN_FUTURE = function(task)
	if rspamd_config:get_api_version() >= 5 then
		local m = task:get_message()
		local dm = m:get_date()
		local dt = task:get_date()
		-- An hour
		if dm - dt > 3600 then
			return true
		end
	end
	
	return false
end
rspamd_config.DATE_IN_PAST = function(task)
	if rspamd_config:get_api_version() >= 5 then
		local m = task:get_message()
		local dm = m:get_date()
		local dt = task:get_date()
		-- A day
		if dt - dm > 86400 then
			return true
		end
	end
	
	return false
end

local function file_exists(filename)
	local file = io.open(filename)
	if file then
		io.close(file)
		return true
	else
		return false
	end
end

if file_exists('hfilter.lua') then
    dofile('hfilter.lua')
end

if file_exists('rspamd.local.lua') then
	dofile('rspamd.local.lua')
end

if file_exists('rspamd.classifiers.lua') then
	dofile('rspamd.classifiers.lua')
end
