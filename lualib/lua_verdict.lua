--[[
Copyright (c) 2019, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

local exports = {}

---[[[
-- @function lua_verdict.get_default_verdict(task)
-- Returns verdict for a task + score if certain, must be called from idempotent filters only
-- Returns string:
-- * `spam`: if message have over reject threshold and has more than one positive rule
-- * `junk`: if a message has between score between [add_header/rewrite subject] to reject thresholds and has more than two positive rules
-- * `passthrough`: if a message has been passed through some short-circuit rule
-- * `ham`: if a message has overall score below junk level **and** more than three negative rule, or negative total score
-- * `uncertain`: all other cases
--]]
local function default_verdict_function(task)
  local result = task:get_metric_result()

  if result then

    if result.passthrough then
      return 'passthrough',nil
    end

    local score = result.score

    local action = result.action

    if action == 'reject' and result.npositive > 1 then
      return 'spam',score
    elseif action == 'no action' then
      if score < 0 or result.nnegative > 3 then
        return 'ham',score
      end
    else
      -- All colors of junk
      if action == 'add header' or action == 'rewrite subject' then
        if result.npositive > 2 then
          return 'junk',score
        end
      end
    end

    return 'uncertain',score
  end
end

local default_possible_verdicts = {
  passthrough = {
    can_learn = false,
    description = 'message has passthrough result',
  },
  spam = {
    can_learn = 'spam',
    description = 'message is likely spam',
  },
  junk = {
    can_learn = 'spam',
    description = 'message is likely possible spam',
  },
  ham = {
    can_learn = 'ham',
    description = 'message is likely ham',
  },
  uncertain = {
    can_learn = false,
    description = 'not certainity in verdict'
  }
}

-- Verdict functions specific for modules
local specific_verdicts = {
  default = {
    callback = default_verdict_function,
    possible_verdicts = default_possible_verdicts
  }
}

local default_verdict = specific_verdicts.default

exports.get_default_verdict = default_verdict.callback
exports.set_verdict_function = function(func, what)
  assert(type(func) == 'function')
  if not what then
    -- Default verdict
    local existing = specific_verdicts.default.callback
    specific_verdicts.default.callback = func
    exports.get_default_verdict = func

    return existing
  else
    local existing = specific_verdicts[what]

    if not existing then
      specific_verdicts[what] = {
        callback = func,
        possible_verdicts = default_possible_verdicts
      }
    else
      existing = existing.callback
    end

    specific_verdicts[what].callback = func
    return existing
  end
end

exports.set_verdict_table = function(verdict_tbl, what)
  assert(type(verdict_tbl) == 'table' and
    type(verdict_tbl.callback) == 'function' and
    type(verdict_tbl.possible_verdicts) == 'table')

  if not what then
    -- Default verdict
    local existing = specific_verdicts.default
    specific_verdicts.default = verdict_tbl
    exports.get_default_verdict = specific_verdicts.default.callback

    return existing
  else
    local existing = specific_verdicts[what]
    specific_verdicts[what] = verdict_tbl
    return existing
  end
end

exports.get_specific_verdict = function(what, task)
  if specific_verdicts[what] then
    return specific_verdicts[what].callback(task)
  end

  return exports.get_default_verdict(task)
end

exports.get_possible_verdicts = function(what)
  local lua_util = require "lua_util"
  if what then
    if specific_verdicts[what] then
      return lua_util.keys(specific_verdicts[what].possible_verdicts)
    end
  else
    return lua_util.keys(specific_verdicts.default.possible_verdicts)
  end

  return nil
end

exports.can_learn = function(verdict, what)
  if what then
    if specific_verdicts[what] and specific_verdicts[what].possible_verdicts[verdict] then
      return specific_verdicts[what].possible_verdicts[verdict].can_learn
    end
  else
    if specific_verdicts.default.possible_verdicts[verdict] then
      return specific_verdicts.default.possible_verdicts[verdict].can_learn
    end
  end

  return nil -- To distinguish from `false` that could happen in can_learn
end

exports.describe = function(verdict, what)
  if what then
    if specific_verdicts[what] and specific_verdicts[what].possible_verdicts[verdict] then
      return specific_verdicts[what].possible_verdicts[verdict].description
    end
  else
    if specific_verdicts.default.possible_verdicts[verdict] then
      return specific_verdicts.default.possible_verdicts[verdict].description
    end
  end

  return nil
end

return exports