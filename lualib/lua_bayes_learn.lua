--[[
Copyright (c) 2022, Vsevolod Stakhov <vsevolod@rspamd.com>

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

-- This file contains functions to simplify bayes classifier auto-learning

local lua_util = require "lua_util"
local lua_verdict = require "lua_verdict"
local logger = require "rspamd_logger"
local N = "lua_bayes"

local exports = {}

exports.can_learn = function(task, is_spam, is_unlearn, category)
  local learn_type = task:get_request_header('Learn-Type')

  if not (learn_type and tostring(learn_type) == 'bulk') then
    local prob = task:get_mempool():get_variable('bayes_prob', 'double')

    if category then
      -- Default thresholds, can be overridden by config
      local thresholds = {
        spam = { value = 0.95, direction = 'gte' },
        ham  = { value = 0.05, direction = 'lte' },
        -- Add more built-in categories if needed
      }
      -- Allow per-task or per-config thresholds
      local th = thresholds[category]
      if task.extra_learn_categories and task.extra_learn_categories[category] then
        th = task.extra_learn_categories[category]
      end

      if prob and th then
        local in_class = false
        if th.direction == 'gte' then
          in_class = prob >= th.value
        elseif th.direction == 'lte' then
          in_class = prob <= th.value
        end

        if in_class then
          return false, string.format(
              'already in class %s; probability %.2f%%',
              category, math.abs((prob - 0.5) * 200.0))
        end
      end
    elseif prob then
      local in_class = false
      local cl
      if is_spam then
        cl = 'spam'
        in_class = prob >= 0.95
      else
        cl = 'ham'
        in_class = prob <= 0.05
      end

      if in_class then
        return false, string.format(
            'already in class %s; probability %.2f%%',
            cl, math.abs((prob - 0.5) * 200.0))
      end
    end
  end

  return true
end

exports.autolearn = function(task, conf)
  local function log_can_autolearn(verdict, score, threshold, category)
    local from = task:get_from('smtp')
    local mime_rcpts = 'undef'
    local mr = task:get_recipients('mime')
    if mr then
      local r_addrs = {}
      for _, r in ipairs(mr) do
        r_addrs[#r_addrs + 1] = r.addr
      end
      if #r_addrs > 0 then
        mime_rcpts = table.concat(r_addrs, ',')
      end
    end

    logger.info(task, 'id: %s, from: <%s>: can autolearn %s: score %s %s %s, mime_rcpts: <%s>',
        task:get_header('Message-Id') or '<undef>',
        from and from[1].addr or 'undef',
        category or verdict,
        string.format("%.2f", score),
        verdict == 'ham' and '<=' or verdict == 'spam' and '>=' or '/',
        threshold,
        mime_rcpts)
  end

  if not task:get_queue_id() then
    lua_util.debugm(N, task, 'no need to autolearn - queue id is missing')
    return
  end

  local verdict, score = lua_verdict.get_specific_verdict("bayes", task)

  if verdict == 'passthrough' then
    -- No need to autolearn
    lua_util.debugm(N, task, 'no need to autolearn - verdict: %s',
        verdict)
    return
  end

  -- Category-aware logic
  if conf.categories then
    for cat, cat_conf in pairs(conf.categories) do
      if verdict == cat and cat_conf.threshold then
        local match = false
        if (cat_conf.direction == 'gte' and score >= cat_conf.threshold) or
           (cat_conf.direction == 'lte' and score <= cat_conf.threshold) then
          match = true
        end
        if match then
          log_can_autolearn(verdict, score, cat_conf.threshold, cat)
          -- Save config for can_learn to read later
          task.extra_learn_categories = conf.categories
          return cat
        end
      end
    end
  end

  local learn_spam, learn_ham = false, false

  if conf.spam_threshold and conf.ham_threshold then
    if verdict == 'spam' then
      if conf.spam_threshold and score >= conf.spam_threshold then
        log_can_autolearn(verdict, score, conf.spam_threshold)
        learn_spam = true
      end
    elseif verdict == 'junk' then
      if conf.junk_threshold and score >= conf.junk_threshold then
        log_can_autolearn(verdict, score, conf.junk_threshold)
        learn_spam = true
      end
    elseif verdict == 'ham' then
      if conf.ham_threshold and score <= conf.ham_threshold then
        log_can_autolearn(verdict, score, conf.ham_threshold)
        learn_ham = true
      end
    end
  elseif conf.learn_verdict then
    if verdict == 'spam' or verdict == 'junk' then
      learn_spam = true
    elseif verdict == 'ham' then
      learn_ham = true
    end
  end

  if conf.check_balance then
    local spam_learns = task:get_mempool():get_variable('spam_learns', 'int64') or 0
    local ham_learns = task:get_mempool():get_variable('ham_learns', 'int64') or 0

    local min_balance = 0.9
    if conf.min_balance then
      min_balance = conf.min_balance
    end

    if spam_learns > 0 or ham_learns > 0 then
      local max_ratio = 1.0 / min_balance
      local spam_learns_ratio = spam_learns / (ham_learns + 1)
      if spam_learns_ratio > max_ratio and learn_spam then
        lua_util.debugm(N, task,
            'skip learning spam, balance is not satisfied: %s < %s; %s spam learns; %s ham learns',
            spam_learns_ratio, min_balance, spam_learns, ham_learns)
        learn_spam = false
      end

      local ham_learns_ratio = ham_learns / (spam_learns + 1)
      if ham_learns_ratio > max_ratio and learn_ham then
        lua_util.debugm(N, task,
            'skip learning ham, balance is not satisfied: %s < %s; %s spam learns; %s ham learns',
            ham_learns_ratio, min_balance, spam_learns, ham_learns)
        learn_ham = false
      end
    end
  end

  if learn_spam then
    return 'spam'
  elseif learn_ham then
    return 'ham'
  end
end

return exports