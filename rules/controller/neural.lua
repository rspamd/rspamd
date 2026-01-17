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
]] --

local neural_common = require "plugins/neural"
local T = require "lua_shape.core"
local ucl = require "ucl"
local lua_util = require "lua_util"
local rspamd_util = require "rspamd_util"
local lua_redis = require "lua_redis"
local rspamd_logger = require "rspamd_logger"

local E = {}
local N = 'neural'

local function get_request_header(task, name)
  local hdr = task:get_request_header(name)
  if type(hdr) == 'table' then
    hdr = hdr[1]
  end
  if hdr then
    return tostring(hdr)
  end
  return nil
end

-- Controller neural plugin

local learn_request_schema = T.table({
  ham_vec = T.array(T.array(T.number())):doc({ summary = "Ham training vectors" }),
  rule = T.string():optional():doc({ summary = "Rule name to train" }),
  spam_vec = T.array(T.array(T.number())):doc({ summary = "Spam training vectors" }),
}):doc({ summary = "Neural network learning request" })

local function handle_learn(task, conn)
  lua_util.debugm(N, task, 'controller.neural: learn called')
  local parser = ucl.parser()
  local ok, err = parser:parse_text(task:get_rawbody())
  if not ok then
    conn:send_error(400, err)
    return
  end
  local req_params = parser:get_object()

  ok, err = learn_request_schema:transform(req_params)
  if not ok then
    conn:send_error(400, err)
    return
  end

  local rule_name = req_params.rule or 'default'
  local rule = neural_common.settings.rules[rule_name]
  local set = neural_common.get_rule_settings(task, rule)
  local version = ((set.ann or E).version or 0) + 1

  neural_common.spawn_train {
    ev_base = task:get_ev_base(),
    ann_key = neural_common.new_ann_key(rule, set, version),
    set = set,
    rule = rule,
    ham_vec = req_params.ham_vec,
    spam_vec = req_params.spam_vec,
    worker = task:get_worker(),
  }

  lua_util.debugm(N, task, 'controller.neural: learn scheduled for rule=%s', rule_name)
  conn:send_string('{"success" : true}')
end

local function handle_status(task, conn, req_params)
  lua_util.debugm(N, task, 'controller.neural: status called')
  local out = {
    rules = {},
  }
  for name, rule in pairs(neural_common.settings.rules) do
    local r = {
      providers = rule.providers,
      fusion = rule.fusion,
      max_inputs = rule.max_inputs,
      settings = {},
      requires_scan = false,
    }
    -- Default: if no providers configured, assume symbols (full scan required)
    local has_providers = type(rule.providers) == 'table' and #rule.providers > 0
    if not has_providers then
      r.requires_scan = true
    else
      for _, p in ipairs(rule.providers) do
        if p.type == 'symbols' then
          r.requires_scan = true
          break
        end
      end
    end
    for sid, set in pairs(rule.settings or {}) do
      if type(set) == 'table' then
        local s = {
          name = set.name,
          symbols_digest = set.digest,
        }
        if set.ann then
          s.ann = {
            version = set.ann.version,
            redis_key = set.ann.redis_key,
            providers_digest = set.ann.providers_digest,
            has_pca = set.ann.pca ~= nil,
          }
        end
        r.settings[sid] = s
      end
    end
    out.rules[name] = r
  end
  conn:send_ucl({ success = true, data = out })
end

-- Return compact configuration for clients (e.g. rspamc) to plan learning
local function handle_config(task, conn, req_params)
  lua_util.debugm(N, task, 'controller.neural: config called')
  local out = {
    rules = {},
  }

  for name, rule in pairs(neural_common.settings.rules) do
    local requires_scan = false
    local has_providers = type(rule.providers) == 'table' and #rule.providers > 0
    if not has_providers then
      requires_scan = true
    else
      for _, p in ipairs(rule.providers) do
        if p.type == 'symbols' then
          requires_scan = true
          break
        end
      end
    end

    local r = {
      requires_scan = requires_scan,
      providers = {},
      recommended_path = requires_scan and '/checkv2' or '/plugins/neural/learn_message',
      settings = {},
    }

    if has_providers then
      for _, p in ipairs(rule.providers) do
        r.providers[#r.providers + 1] = { type = p.type }
      end
    end

    for _, set in pairs(rule.settings or {}) do
      if type(set) == 'table' then
        r.settings[#r.settings + 1] = set.name
      end
    end

    out.rules[name] = r
  end

  conn:send_ucl({ success = true, data = out })
end

-- Train directly from a message for providers that don't require full /checkv2
-- Headers:
--  - ANN-Train or Class: 'spam' | 'ham'
--  - Rule: rule name (optional, default 'default')
local function handle_learn_message(task, conn)
  lua_util.debugm(N, task, 'controller.neural: learn_message called')

  -- Ensure the message is parsed so LLM providers can access text parts
  local ok_parse = task:process_message()
  if not ok_parse then
    lua_util.debugm(N, task, 'controller.neural: cannot process message MIME, abort')
    conn:send_error(400, 'cannot parse message for learning')
    return
  end

  local cls = get_request_header(task, 'ANN-Train') or get_request_header(task, 'Class')
  if not cls then
    conn:send_error(400, 'missing class header (ANN-Train or Class)')
    return
  end

  local learn_type = tostring(cls):lower()
  if learn_type ~= 'spam' and learn_type ~= 'ham' then
    conn:send_error(400, 'unsupported class (expected spam or ham)')
    return
  end

  local rule_name = get_request_header(task, 'Rule') or 'default'
  local rule = neural_common.settings.rules[rule_name]
  if not rule then
    conn:send_error(400, 'unknown rule')
    return
  end

  -- Check if this configuration requires full scan
  -- Only symbols collection requires full scan; metatokens can be computed directly
  local has_providers = type(rule.providers) == 'table' and #rule.providers > 0

  if not has_providers and not rule.disable_symbols_input then
    -- No providers means full symbols will be used (not just metatokens)
    lua_util.debugm(N, task,
      'controller.neural: learn_message refused: no providers configured, symbols collection requires full scan for rule=%s',
      rule_name)
    conn:send_error(400, 'rule requires full /checkv2 scan (no providers configured, full symbols collection required)')
    return
  end

  -- Check if any provider requires full scan (only symbols provider does)
  if has_providers then
    for _, p in ipairs(rule.providers) do
      if p.type == 'symbols' then
        lua_util.debugm(N, task,
          'controller.neural: learn_message refused due to symbols provider requiring full scan for rule=%s',
          rule_name)
        conn:send_error(400, 'rule requires full /checkv2 scan (symbols provider present)')
        return
      end
    end
  end

  -- At this point:
  -- - We have providers that don't require full scan (e.g., LLM)
  -- - Metatokens can be computed directly from the message
  -- - Controller training is allowed

  local set = neural_common.get_rule_settings(task, rule)
  if not set then
    lua_util.debugm(N, task, 'controller.neural: no settings resolved for rule=%s; falling back to first available set',
      rule_name)
    for sid, s in pairs(rule.settings or {}) do
      if type(s) == 'table' then
        set = s
        set.name = set.name or sid
        break
      end
    end
  end

  if set then
    lua_util.debugm(N, task, 'controller.neural: set found for rule=%s, symbols=%s, name=%s',
      rule_name, set.symbols and #set.symbols or "nil", set.name)
  end

  -- Derive redis base key even if ANN not yet initialized
  local redis_base
  if set and set.ann and set.ann.redis_key then
    redis_base = set.ann.redis_key
  elseif set then
    local ok, prefix = pcall(neural_common.redis_ann_prefix, rule, set.name)
    if ok and prefix then
      redis_base = prefix
      lua_util.debugm(N, task, 'controller.neural: derived redis base key for rule=%s set=%s -> %s', rule_name, set.name,
        redis_base)
    end
  end

  if not set or not redis_base then
    lua_util.debugm(N, task, 'controller.neural: invalid set or redis key for learning; set=%s ann=%s',
      tostring(set ~= nil), set and tostring(set.ann ~= nil) or 'nil')
    conn:send_error(400, 'invalid rule settings for learning')
    return
  end

  -- Ensure profile exists for this set
  if not set.ann then
    local version = 0
    local ann_key = neural_common.new_ann_key(rule, set, version)

    local profile = {
      symbols = set.symbols,
      redis_key = ann_key,
      version = version,
      digest = set.digest,
      distance = 0,
      providers_digest = neural_common.providers_config_digest(rule.providers, rule),
    }

    local profile_serialized = ucl.to_format(profile, 'json-compact', true)

    lua_util.debugm(N, task, 'controller.neural: creating new profile for %s:%s at %s',
      rule.prefix, set.name, ann_key)

    -- Store the profile in Redis sorted set
    lua_redis.redis_make_request(task,
      rule.redis,
      nil,
      true, -- is write
      function(err, _)
        if err then
          rspamd_logger.errx(task, 'cannot store ANN profile for %s:%s at %s : %s',
            rule.prefix, set.name, profile.redis_key, err)
        else
          lua_util.debugm(N, task, 'created new ANN profile for %s:%s, data stored at prefix %s',
            rule.prefix, set.name, profile.redis_key)
        end
      end,
      'ZADD', -- command
      { set.prefix, tostring(rspamd_util.get_time()), profile_serialized }
    )

    -- Update redis_base to use the new ann_key
    redis_base = ann_key
  end

  local function after_collect(vec)
    lua_util.debugm(N, task, 'controller.neural: learn_message after_collect, vector=%s', type(vec))
    if not vec then
      lua_util.debugm(N, task,
        'controller.neural: no vector collected; skip training')
      conn:send_error(400, 'no vector collected')
      return
    end

    if type(vec) ~= 'table' then
      conn:send_error(500, 'failed to build training vector')
      return
    end

    -- Preview vector for debugging
    local function preview_vector(v)
      local n = #v
      local limit = math.min(n, 8)
      local parts = {}
      for i = 1, limit do
        parts[#parts + 1] = string.format('%.4f', tonumber(v[i]) or 0)
      end
      return n, table.concat(parts, ',')
    end

    local vlen, vhead = preview_vector(vec)
    lua_util.debugm(N, task, 'controller.neural: vector size=%s head=[%s]', vlen, vhead)

    local compressed = rspamd_util.zstd_compress(table.concat(vec, ';'))
    local target_key = string.format('%s_%s_set', redis_base, learn_type)

    local function learn_vec_cb(redis_err)
      if redis_err then
        rspamd_logger.errx(task, 'cannot store train vector for %s:%s: %s',
          rule.prefix, set.name, redis_err)
        conn:send_error(500, 'cannot store train vector')
      else
        lua_util.debugm(N, task, 'controller.neural: stored train vector for rule=%s key=%s bytes=%s', rule_name,
          target_key, #compressed)
        conn:send_ucl({ success = true, stored = #compressed, key = target_key })
      end
    end

    lua_redis.redis_make_request(task,
      rule.redis,
      nil,
      true,
      learn_vec_cb,
      'SADD',
      { target_key, compressed }
    )
  end

  if rule.providers and #rule.providers > 0 then
    lua_util.debugm(N, task, 'controller.neural: collecting features for rule=%s', rule_name)
    neural_common.collect_features_async(task, rule, set, 'train', after_collect)
  else
    -- Should not reach here due to early return
    conn:send_error(400, 'rule requires full /checkv2 scan (no providers configured)')
  end
end

local function handle_train(task, conn, req_params)
  local rule_name = req_params.rule or 'default'
  local rule = neural_common.settings.rules[rule_name]
  if not rule then
    conn:send_error(400, 'unknown rule')
    return
  end
  -- Trigger check_anns to evaluate training conditions
  rspamd_config:add_periodic(task:get_ev_base(), 0.0, function()
    return 0.0
  end)
  conn:send_ucl({ success = true, message = 'training scheduled check' })
end

return {
  learn = {
    handler = handle_learn,
    enable = true,
    need_task = true,
  },
  config = {
    handler = handle_config,
    enable = true,
    need_task = false,
  },
  learn_message = {
    handler = handle_learn_message,
    enable = true,
    need_task = true,
  },
  status = {
    handler = handle_status,
    enable = true,
    need_task = false,
  },
  train = {
    handler = handle_train,
    enable = true,
    need_task = false,
  },
}
