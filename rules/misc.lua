--[[
Copyright (c) 2011-2015, Vsevolod Stakhov <vsevolod@highsecure.ru>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]--

-- This is main lua config file for rspamd

local util = require "rspamd_util"
local rspamd_regexp = require "rspamd_regexp"
local rspamd_logger = require "rspamd_logger"

local reconf = config['regexp']

-- Uncategorized rules
local subject_re = rspamd_regexp.create('/^(?:(?:Re|Fwd|Fw|Aw|Antwort|Sv):\\s*)+(.+)$/i')

-- Local rules
local r_bgcolor = '/BGCOLOR=/iP'
local r_font_color = '/font color=[\\"\']?\\#FFFFFF[\\"\']?/iP'
reconf['R_WHITE_ON_WHITE'] = string.format('(!(%s) & (%s))', r_bgcolor, r_font_color)
reconf['R_FLASH_REDIR_IMGSHACK'] = '/^(?:http:\\/\\/)?img\\d{1,5}\\.imageshack\\.us\\/\\S+\\.swf/U'

-- Different text parts
rspamd_config.R_PARTS_DIFFER = function(task)
  local distance = task:get_mempool():get_variable('parts_distance', 'double')

  if distance then
    local nd = tonumber(distance)
    -- ND is relation of different words to total words
    if nd >= 0.5 then
      local tw = task:get_mempool():get_variable('total_words', 'int')

      if tw then
        if tw > 30 then
          -- We are confident about difference
          local score = (nd - 0.5) * 2.0
        else
          -- We are not so confident about difference
          local score = (nd - 0.5)
        end
        task:insert_result('R_PARTS_DIFFER', score, tostring(100.0 * nd) .. '%')
      end
    end
  end

  return false
end

-- Date issues
rspamd_config.MISSING_DATE = function(task)
	if rspamd_config:get_api_version() >= 5 then
		if not task:get_header_raw('Date') then
			return true
		end
	end

	return false
end
rspamd_config.DATE_IN_FUTURE = function(task)
	if rspamd_config:get_api_version() >= 5 then
		local dm = task:get_date{format = 'message'}
		local dt = task:get_date{format = 'connect'}
		-- An 2 hour
		if dm > 0 and dm - dt > 7200 then
			return true
		end
	end

	return false
end
rspamd_config.DATE_IN_PAST = function(task)
	if rspamd_config:get_api_version() >= 5 then
    local dm = task:get_date{format = 'message', gmt = true}
    local dt = task:get_date{format = 'connect', gmt = true}
		-- A day
		if dm > 0 and dt - dm > 86400 then
			return true
		end
	end

	return false
end

rspamd_config.R_SUSPICIOUS_URL = function(task)
    local urls = task:get_urls()

    if urls then
      for i,u in ipairs(urls) do
        if u:is_obscured() then
          task:insert_result('R_SUSPICIOUS_URL', 1.0, u:get_host())
        end
      end
    end
    return false
end

rspamd_config.SUBJ_ALL_CAPS = {
  callback = function(task)
    local sbj = task:get_header('Subject')

    if sbj then
      local stripped_subject = subject_re:search(sbj, false, true)
      if stripped_subject and stripped_subject[1] and stripped_subject[1][2] then
        sbj = stripped_subject[1][2]
      end

      if util.is_uppercase(sbj) then
        return true
      end
    end

    return false
  end,
  score = 3.0,
  group = 'headers',
  description = 'All capital letters in subject'
}

rspamd_config.LONG_SUBJ = {
  callback = function(task)
    local sbj = task:get_header('Subject')
    if sbj and util.strlen_utf8(sbj) > 200 then
      return true
    end
    return false
  end,

  score = 3.0,
  group = 'headers',
  description = 'Subject is too long'
}

rspamd_config.BROKEN_HEADERS = {
  callback = function(task)
    if task:has_flag('broken_headers') then
      return true
    end

    return false
  end,
  score = 1.0,
  group = 'headers',
  description = 'Headers structure is likely broken'
}

rspamd_config.HEADER_RCONFIRM_MISMATCH = {
  callback = function (task)
    local header_from = nil
    local cread = task:get_header('X-Confirm-Reading-To')

    if task:has_from('mime') then
      header_from  = task:get_from('mime')[1]
    end

    local header_cread = nil
    if cread then
      local headers_cread = util.parse_mail_address(cread)
      if headers_cread then header_cread = headers_cread[1] end
    end

    if header_from and header_cread then
      if not string.find(header_from['addr'], header_cread['addr']) then
        return true
      end
    end

    return false
  end,

  score = 2.0,
  group = 'headers',
  description = 'Read confirmation address is different to from address'
}

rspamd_config.HEADER_FORGED_MDN = {
  callback = function (task)
    local mdn = task:get_header('Disposition-Notification-To')
    local header_rp = nil

    if task:has_from('smtp') then
      header_rp = task:get_from('smtp')[1]
    end

    -- Parse mail addr
    local header_mdn = nil
    if mdn then
      local headers_mdn = util.parse_mail_address(mdn)
      if headers_mdn then header_mdn = headers_mdn[1] end
    end

    if header_mdn and not header_rp  then return true end
    if header_rp  and not header_mdn then return false end

    if header_mdn and header_mdn['addr'] ~= header_rp['addr'] then
      return true
    end

    return false
  end,

  score = 2.0,
  group = 'headers',
  description = 'Read confirmation address is different to return path'
}

local headers_unique = {
  'Content-Type',
  'Content-Transfer-Encoding',
  'Date',
  'Message-ID'
}

rspamd_config.MULTIPLE_UNIQUE_HEADERS = {
  callback = function (task)
    local res = 0
    local res_tbl = {}

    for i,hdr in ipairs(headers_unique) do
      local h = task:get_header_full(hdr)

      if h and #h > 1 then
        res = res + 1
        table.insert(res_tbl, hdr)
      end
    end

    if res > 0 then
      return true,res,table.concat(res_tbl, ',')
    end

    return false
  end,

  score = 5.0,
  group = 'headers',
  description = 'Repeated unique headers'
}
