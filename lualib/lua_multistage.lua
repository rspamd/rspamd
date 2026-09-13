--[[
Copyright (c) 2026, Vsevolod Stakhov <vsevolod@rspamd.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
]]--

-- Connect checks using the effective SMTP identity to modules that rewrite it.
-- Register only actual symbols, independently of plugin loading order. The
-- scheduler then propagates the rewriter's input requirements to each consumer.
local configurations = setmetatable({}, { __mode = 'k' })

local function register(cfg, symbol, kind, other_kind)
  local state = configurations[cfg]

  if not state then
    state = { consumers = {}, rewriters = {} }
    configurations[cfg] = state
  end

  if state[kind][symbol] then
    return
  end

  state[kind][symbol] = true

  for other in pairs(state[other_kind]) do
    if kind == 'consumers' then
      cfg:register_dependency(symbol, other)
    else
      cfg:register_dependency(other, symbol)
    end
  end
end

return {
  register_connection_consumer = function(cfg, symbol)
    register(cfg, symbol, 'consumers', 'rewriters')
  end,
  register_connection_rewriter = function(cfg, symbol)
    register(cfg, symbol, 'rewriters', 'consumers')
  end,
}
