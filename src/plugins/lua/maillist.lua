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

if confighelp then
  return
end

-- Module for checking mail list headers
local N = 'maillist'
local symbol = 'MAILLIST'
local lua_util = require "lua_util"
-- EZMLM
-- Mailing-List: .*run by ezmlm
-- Precedence: bulk
-- List-Post: <mailto:
-- List-Help: <mailto:
-- List-Unsubscribe: <mailto:[a-zA-Z\.-]+-unsubscribe@
-- List-Subscribe: <mailto:[a-zA-Z\.-]+-subscribe@
-- RFC 2919 headers exist
local function check_ml_ezmlm(task)
  -- Mailing-List
  local header = task:get_header('mailing-list')
  if not header or not string.find(header, 'ezmlm$') then
    return false
  end
  -- Precedence
  header = task:get_header('precedence')
  if not header or not string.match(header, '^bulk$') then
    return false
  end
  -- Other headers
  header = task:get_header('list-post')
  if not header or not string.find(header, '^<mailto:') then
    return false
  end
  header = task:get_header('list-help')
  if not header or not string.find(header, '^<mailto:') then
    return false
  end
  -- Subscribe and unsubscribe
  header = task:get_header('list-subscribe')
  if not header or not string.find(header, '<mailto:[a-zA-Z.-]+-subscribe@') then
    return false
  end
  header = task:get_header('list-unsubscribe')
  if not header or not string.find(header, '<mailto:[a-zA-Z.-]+-unsubscribe@') then
    return false
  end

  return true
end

-- GNU Mailman
-- Two major versions currently in use and they use slightly different headers
-- Mailman2: https://code.launchpad.net/~mailman-coders/mailman/2.1
-- Mailman3: https://gitlab.com/mailman/mailman
local function check_ml_mailman(task)
  local header = task:get_header('X-Mailman-Version')
  if not header then
    return false
  end
  local mm_version = header:match('^([23])%.')
  if not mm_version then
    lua_util.debugm(N, task, 'unknown Mailman version: %s', header)
    return false
  end
  lua_util.debugm(N, task, 'checking Mailman %s headers', mm_version)

  -- XXX Some messages may not contain Precedence, but they are rare:
  -- http://bazaar.launchpad.net/~mailman-coders/mailman/2.1/revision/1339
  header = task:get_header('Precedence')
  if not header or (header ~= 'bulk' and header ~= 'list') then
    return false
  end

  -- Mailmain 3 allows to disable all List-* headers in settings, but by default it adds them.
  -- In all other cases all Mailman message should have List-Id header
  if not task:has_header('List-Id') then
    return false
  end

  if mm_version == '2' then
    -- X-BeenThere present in all Mailman2 messages
    if not task:has_header('X-BeenThere') then
      return false
    end
    -- X-List-Administrivia: is only added to messages Mailman creates and
    -- sends out of its own accord
    header = task:get_header('X-List-Administrivia')
    if header and header == 'yes' then
      -- not much elase we can check, Subjects can be changed in settings
      return true
    end
  else -- Mailman 3
    -- XXX not Mailman3 admin messages have this headers, but one
    -- which don't usually have List-* headers examined below
    if task:has_header('List-Administrivia') then
      return true
    end
  end

  -- List-Archive and List-Post are optional, check other headers
  for _, h in ipairs({'List-Help', 'List-Subscribe', 'List-Unsubscribe'}) do
    header = task:get_header(h)
    if not (header and header:find('<mailto:', 1, true)) then
      return false
    end
  end

  return true
end

-- Subscribe.ru
-- List-Id: <*.subscribe.ru>
-- List-Help: <https://subscribe.ru/catalog/*>
-- List-Subscribe: <mailto:*-sub@subscribe.ru>
-- List-Unsubscribe: <mailto:*-unsub@subscribe.ru>
-- List-Archive:  <https://subscribe.ru/archive/*>
-- List-Owner: <mailto:*@subscribe.ru>
-- List-Post: NO
local function check_ml_subscriberu(task)
  -- List-Id
  local header = task:get_header('list-id')
  if not (header and header:find('^<.*%.subscribe%.ru>$')) then
    return false
  end
  -- Other headers
  header = task:get_header('list-archive')
  if not (header and header:find('^<https?://subscribe%.ru/archive/.+>$')) then
    return false
  end
  header = task:get_header('list-owner')
  if not (header and header:find('^<mailto:.+@subscribe%.ru>$')) then
    return false
  end
  header = task:get_header('list-help')
  if not (header and header:find('^<https?://subscribe%.ru/catalog/.+>$')) then
    return false
  end
  -- Subscribe and unsubscribe
  header = task:get_header('list-subscribe')
  if not (header and header:find('^<mailto:.+-sub@subscribe%.ru>$')) then
    return false
  end
  header = task:get_header('list-unsubscribe')
  if not (header and header:find('^<mailto:.+-unsub@subscribe%.ru>$')) then
    return false
  end

  return true

end

-- Google groups detector
-- header exists X-Google-Loop
-- RFC 2919 headers exist
--
local function check_ml_googlegroup(task)
  return task:has_header('X-Google-Loop') or task:has_header('X-Google-Group-Id')
end

-- CGP detector
-- X-Listserver = CommuniGate Pro LIST
-- RFC 2919 headers exist
--
local function check_ml_cgp(task)
  local header = task:get_header('X-Listserver')

  if not header or string.sub(header, 0, 20) ~= 'CommuniGate Pro LIST' then
    return false
  end

  return true
end

-- RFC 2919 headers
local function check_generic_list_headers(task)
  local score = 0
  local has_subscribe, has_unsubscribe

  if task:has_header('List-Id') then
    score = score + 0.75
    lua_util.debugm(N, task, 'has List-Id header, score = %s', score)
  end

  local header = task:get_header('Precedence')
  if header and (header == 'list' or header == 'bulk') then
    score = score + 0.25
    lua_util.debugm(N, task, 'has header "Precedence: %s", score = %s',
        header, score)
  end

  if task:has_header('List-Archive') then
    score = score + 0.125
    lua_util.debugm(N, task, 'has header List-Archive, score = %s',
        score)
  end
  if task:has_header('List-Owner') then
    score = score + 0.125
    lua_util.debugm(N, task, 'has header List-Owner, score = %s',
        score)
  end
  if task:has_header('List-Help') then
    score = score + 0.125
    lua_util.debugm(N, task, 'has header List-Help, score = %s',
        score)
  end

  -- Subscribe and unsubscribe
  if task:has_header('List-Subscribe') then
    has_subscribe = true
    score = score + 0.125
    lua_util.debugm(N, task, 'has header List-Subscribe, score = %s',
        score)
  end
  if task:has_header('List-Unsubscribe') then
    has_unsubscribe = true
    score = score + 0.125
    lua_util.debugm(N, task, 'has header List-Unsubscribe, score = %s',
        score)
  end

  if task:has_header('X-Loop') then
    score = score + 0.125
    lua_util.debugm(N, task, 'has header X-Loop, score = %s',
        score)
  end

  if has_subscribe and has_unsubscribe then
    score = score + 0.25
  elseif (has_unsubscribe) then
    score = score - 0.25
  elseif (has_subscribe) then
    score = score - 0.75
  end

  lua_util.debugm(N, task, 'final maillist score %s', score)
  return score
end


-- RFC 2919 headers exist
local function check_maillist(task)
  local score = check_generic_list_headers(task)
  if score >= 1 then
    if check_ml_ezmlm(task) then
      task:insert_result(symbol, 1, 'ezmlm')
    elseif check_ml_mailman(task) then
      task:insert_result(symbol, 1, 'mailman')
    elseif check_ml_subscriberu(task) then
      task:insert_result(symbol, 1, 'subscribe.ru')
    elseif check_ml_googlegroup(task) then
      task:insert_result(symbol, 1, 'googlegroups')
    elseif check_ml_cgp(task) then
      task:insert_result(symbol, 1, 'cgp')
    else
      if score > 2 then score = 2 end
      task:insert_result(symbol, 0.5 * score, 'generic')
    end
  end
end



-- Configuration
local opts =  rspamd_config:get_all_opt('maillist')
if opts then
  if opts['symbol'] then
    symbol = opts['symbol']
    rspamd_config:register_symbol({
      name = symbol,
      callback = check_maillist
    })
  end
end
