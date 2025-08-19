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
local ts = require("tableshape").types
local ucl = require "ucl"
local lua_util = require "lua_util"

local E = {}

-- Controller neural plugin

local learn_request_schema = ts.shape {
  ham_vec = ts.array_of(ts.array_of(ts.number)),
  rule = ts.string:is_optional(),
  spam_vec = ts.array_of(ts.array_of(ts.number)),
}

local function handle_learn(task, conn)
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

  conn:send_string('{"success" : true}')
end

local function handle_status(task, conn, req_params)
  local out = {
    rules = {},
  }
  for name, rule in pairs(neural_common.settings.rules) do
    local r = {
      providers = rule.providers,
      fusion = rule.fusion,
      max_inputs = rule.max_inputs,
      settings = {},
    }
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
  status = {
    handler = handle_status,
    enable = false,
    need_task = false,
  },
  train = {
    handler = handle_train,
    enable = true,
    need_task = false,
  },
}
