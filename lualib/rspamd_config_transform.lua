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

local logger = require "rspamd_logger"
local fun = require "fun"

local function override_defaults(def, override)
  if not override then
    return def
  end
  for k,v in pairs(override) do
    if k ~= 'selector' and k ~= 'backend' then
      if def[k] then
        if type(v) == 'table' then
          override_defaults(def[k], v)
        else
          def[k] = v
        end
      else
        def[k] = v
      end
    end
  end
end

local function metric_pairs(t)
  -- collect the keys
  local keys = {}
  local mt = getmetatable(t)
  local implicit_array = mt and mt.class and mt.class == 'ucl.type.impl_array'

  local function gen_keys(tbl)
    if implicit_array then
      for _,v in ipairs(tbl) do
        if v.name then
          table.insert(keys, {v.name, v})
          v.name = nil
        else
          -- Very tricky to distinguish:
          -- group {name = "foo" ... } + group "blah" { ... }
          for gr_name,gr in pairs(v) do
            if type(gr_name) ~= 'number' then
              table.insert(keys, {gr_name, gr})
            end
          end
        end
      end
    else
      if tbl.name then
        table.insert(keys, {tbl.name, tbl})
        tbl.name = nil
      else
        for k,v in pairs(tbl) do
          if type(k) ~= 'number' then
            table.insert(keys, {k, v})
          end
        end
      end
    end
  end

  gen_keys(t)

  -- return the iterator function
  local i = 0
  return function()
    i = i + 1
    if keys[i] then
      return keys[i][1], keys[i][2]
    end
  end
end

local function group_transform(cfg, k, v)
  if v.name then k = v.name end

  local new_group = {
    symbols = {}
  }

  if v.enabled then new_group.enabled = v.enabled end
  if v.disabled then new_group.disabled = v.disabled end
  if v.max_score then new_group.max_score = v.max_score end

  if v.symbol then
    for sk,sv in metric_pairs(v.symbol) do
      if sv.name then
        sk = sv.name
        sv.name = nil -- Remove field
      end

      new_group.symbols[sk] = sv
    end
  end

  if not cfg.group then cfg.group = {} end

  if cfg.group[k] then
    local merged = override_defaults(new_group, cfg.group[k])
    cfg.group[k] = merged
  else
    cfg.group[k] = new_group
  end

  logger.warnx("overriding group %s from the legacy metric settings", k)
end

local function symbol_transform(cfg, k, v)
  -- first try to find any group where there is a definition of this symbol
  for gr_n, gr in pairs(cfg.group) do
    if gr.symbols and gr.symbols[k] then
      -- We override group symbol with ungrouped symbol
      logger.warnx("overriding group symbol %s in the group %s", k, gr_n)
      gr.symbols[k] = override_defaults(gr.symbols[k], v)
      return
    end
  end

  -- Otherwise we just use group 'ungrouped'
  if not cfg.group.ungrouped then
    cfg.group.ungrouped = {
      symbols = {}
    }
  end

  cfg.group.ungrouped.symbols[k] = v
  logger.warnx("adding symbol %s to the group 'ungrouped'", k)
end

local function test_groups(groups)
  local all_symbols = {}
  for gr_name, gr in pairs(groups) do
    if not gr.symbols then
      logger.errx('group %s has no symbols', gr_name)
    else
      for sn,_ in pairs(gr.symbols) do
        if all_symbols[sn] then
          logger.errx('symbol %s has registered in multiple groups: %s and %s',
              sn, all_symbols[sn], gr_name)
        else
          all_symbols[sn] = gr_name
        end
      end
    end
  end
end

local function convert_metric(cfg, metric)
  if metric.actions then
    cfg.actions = override_defaults(metric.actions)
    logger.warnx("overriding actions from the legacy metric settings")
  end
  if metric.unknown_weight then
    cfg.actions.unknown_weight = metric.unknown_weight
  end

  if metric.subject then
    logger.warnx("overriding subject from the legacy metric settings")
    cfg.actions.subject = metric.subject
  end

  if metric.group then
    for k, v in metric_pairs(metric.group) do
      group_transform(cfg, k, v)
    end
  end

  if metric.symbol then
    for k, v in metric_pairs(metric.symbol) do
      symbol_transform(cfg, k, v)
    end
  end

  return cfg
end

return function(cfg)
  local ret = false

  if cfg['metric'] then
    for _, v in metric_pairs(cfg.metric) do
      cfg = convert_metric(cfg, v)
    end
    ret = true
  end

  if not cfg.actions then
    logger.errx('no actions defined')
  end

  if not cfg.group then
    logger.errx('no symbol groups defined')
  else
    test_groups(cfg.group)
  end

  return ret, cfg
end
