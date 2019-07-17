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

-- MailMan (the gnu mailing list manager)
-- Precedence: bulk [or list for v2]
-- List-Help: <mailto:
-- List-Post: <mailto:
-- List-Subscribe: .*<mailto:.*=subscribe>
-- List-Unsubscribe: .*<mailto:.*=unsubscribe>
-- List-Archive:
-- X-Mailman-Version: \d
-- RFC 2919 headers exist
local function check_ml_mailman(task)
  -- Mailing-List
  local header = task:get_header('x-mailman-version')
  if not header or not string.find(header, '^%d') then
    return false
  end
  -- Precedence
  header = task:get_header('precedence')
  if not header or (header ~= 'bulk' and header ~= 'list') then
    return false
  end
  -- For reminders we have other headers than for normal messages
  header = task:get_header('x-list-administrivia')
  local subject = task:get_header('subject')
  if (header and string.find(header, 'yes')) or
      (subject and string.find(subject, 'mailing list memberships reminder$')) then
    if not task:get_header('errors-to') or not task:get_header('x-beenthere') then
      return false
    end
    header = task:get_header('x-no-archive')
    if not header or not string.find(header, 'yes') then
      return false
    end
    return true
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
  if not header or not string.find(header, '<mailto:.*=subscribe>') then
    return false
  end
  header = task:get_header('list-unsubscribe')
  if not header or not string.find(header, '<mailto:.*=unsubscribe>') then
    return false
  end

  return true

end

-- Subscribe.ru
-- Precedence: normal
-- List-Id: <.*.subscribe.ru>
-- List-Help: <http://subscribe.ru/catalog/.*>
-- List-Subscribe: <mailto:.*-sub@subscribe.ru>
-- List-Unsubscribe: <mailto:.*-unsub@subscribe.ru>
-- List-Archive:  <http://subscribe.ru/archive/.*>
-- List-Owner: <mailto:.*-owner@subscribe.ru>
-- List-Post: NO
local function check_ml_subscriberu(task)
  -- List-Id
  local header = task:get_header('list-id')
  if not header or not string.find(header, '^<.*%.subscribe%.ru>$') then
    return false
  end
  -- Precedence
  header = task:get_header('precedence')
  if not header or not string.match(header, '^normal$') then
    return false
  end
  -- Other headers
  header = task:get_header('list-archive')
  if not header or not string.find(header, '^<http://subscribe.ru/archive/.*>$') then
    return false
  end
  header = task:get_header('list-owner')
  if not header or not string.find(header, '^<mailto:.*-owner@subscribe.ru>$') then
    return false
  end
  header = task:get_header('list-help')
  if not header or not string.find(header, '^<http://subscribe.ru/catalog/.*>$') then
    return false
  end
  -- Subscribe and unsubscribe
  header = task:get_header('list-subscribe')
  if not header or not string.find(header, '^<mailto:.*-sub@subscribe.ru>$') then
    return false
  end
  header = task:get_header('list-unsubscribe')
  if not header or not string.find(header, '^<mailto:.*-unsub@subscribe.ru>$') then
    return false
  end

  return true

end

-- Google groups detector
-- header exists X-Google-Loop
-- RFC 2919 headers exist
--
local function check_ml_googlegroup(task)
  local header = task:get_header('X-Google-Loop')

  if not header then
    header = task:get_header('X-Google-Group-Id')

    if not header then
      return false
    end
  end

  return true
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

  if task:get_header_count('list-id') then
    lua_util.debugm(N, task, 'has header List-Id, score = %s', score)
    score = score + 0.75
  end

  local header = task:get_header('Precedence')
  if header and (header == 'list' or header == 'bulk') then
    lua_util.debugm(N, task, 'has header Precedence: %s, score = %s',
        header, score)

    score = score + 0.25
  end

  if task:get_header_count('list-archive') == 1 then
    lua_util.debugm(N, task, 'has header List-Archive, score = %s',
        score)
    score = score + 0.125
  end
  if task:get_header_count('list-owner') == 1 then
    lua_util.debugm(N, task, 'has header List-Owner, score = %s',
        score)
    score = score + 0.125
  end
  if task:get_header_count('list-help') == 1 then
    lua_util.debugm(N, task, 'has header List-Help, score = %s',
        score)
    score = score + 0.125
  end

  -- Subscribe and unsubscribe
  if task:get_header_count('list-subscribe') == 1 then
    lua_util.debugm(N, task, 'has header List-Subscribe, score = %s',
        score)
    score = score + 0.125
    has_subscribe = true
  end
  if task:get_header_count('list-unsubscribe') == 1 then
    lua_util.debugm(N, task, 'has header List-Subscribe, score = %s',
        score)
    score = score + 0.125
    has_unsubscribe = true
  end

  if task:get_header_count('x-loop') == 1 then
    lua_util.debugm(N, task, 'has header x-loop, score = %s',
        score)
    score = score + 0.125
  end

  if has_subscribe and has_unsubscribe then
    score = score + 0.25
  elseif (has_subscribe or has_unsubscribe) then
    score = score - 0.75
  end

  lua_util.debugm(N, task, 'final maillist score %s', score)
  return score
end


-- RFC 2919 headers exist
local function check_maillist(task)
  local score = check_generic_list_headers(task)
  if score > 1 then
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
