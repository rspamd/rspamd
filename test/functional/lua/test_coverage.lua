--[[
-- This should be the very first file executed during a test
-- otherwise coverage will be partly missed
--]]
local logger = require "rspamd_logger"
local mempool = require "rspamd_mempool"
local loaded, luacov = pcall(require, 'luacov.runner')
if not loaded then
  logger.errx('luacov is not loaded, will not collect coverage')
  return
end

luacov.init()

local pool = mempool.create()
-- we don't need the pool, we need userdata to put __gc() on it
-- __gc() is not called for tables, that't why there is such trick
-- so, we are free to clean memory, let's do this :)
pool:destroy()

local woker_name

rspamd_config:add_on_load(function(cfg, ev_base, worker)
  woker_name = worker:get_name()
  local stats_path = rspamd_paths["DBDIR"] .. '/' .. woker_name .. '.luacov.stats.out'
  local config = luacov.load_config()
  config.statsfile = stats_path
end)

-- use global variable to prevent the object from being GC'ed too early
__GLOBAL_COVERAGE_WATCHDOG = {pool = pool}

local mt = {
  __gc = function()
  --[[
  -- We could've used finish_script but in that case some coverage would be missed:
  -- pool destructors are executed after finish_scripts (when Lua state is terminated and that's
  -- how we can collect coverage of cove executed there
  --]]
    if woker_name then
      luacov.shutdown()
    end
  end
}

debug.setmetatable(__GLOBAL_COVERAGE_WATCHDOG.pool, mt)
