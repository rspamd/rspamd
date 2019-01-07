--[[
Copyright (c) 2017, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

local rspamd_regexp = require "rspamd_regexp"
local util = require "rspamd_util"

-- Uncategorized rules
local subject_re = rspamd_regexp.create('/^(?:(?:Re|Fwd|Fw|Aw|Antwort|Sv):\\s*)+(.+)$/i')

local function test_subject(task, check_function, rate)
  local function normalize_linear(a, x)
      local f = a * x
      return true, (( f < 1 ) and f or 1), tostring(x)
  end

  local sbj = task:get_header('Subject')

  if sbj then
    local stripped_subject = subject_re:search(sbj, false, true)
    if stripped_subject and stripped_subject[1] and stripped_subject[1][2] then
      sbj = stripped_subject[1][2]
    end

    local l = util.strlen_utf8(sbj)
    if check_function(sbj, l) then
      return normalize_linear(rate, l)
    end
  end

  return false
end

rspamd_config.SUBJ_ALL_CAPS = {
  callback = function(task)
    local caps_test = function(sbj)
      return util.is_uppercase(sbj)
    end
    return test_subject(task, caps_test, 1.0/40.0)
  end,
  score = 3.0,
  group = 'subject',
  type = 'mime',
  description = 'All capital letters in subject'
}

rspamd_config.LONG_SUBJ = {
  callback = function(task)
    local length_test = function(_, len)
      return len > 200
    end
    return test_subject(task, length_test, 1.0/400.0)
  end,
  score = 3.0,
  group = 'subject',
  type = 'mime',
  description = 'Subject is too long'
}