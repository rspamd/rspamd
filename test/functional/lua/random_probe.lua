-- Every forked process that runs on_load callbacks logs its first
-- math.random() draws; the robot suite checks that they differ between
-- processes (they used to be identical because the Lua PRNG was seeded
-- before the fork).
local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"

rspamd_config:add_on_load(function(_, _, worker)
  local draws = {}
  for i = 1, 3 do
    draws[i] = string.format('%.15f', math.random())
  end
  rspamd_logger.infox('RANDOM_PROBE type=%s pid=%s draws=%s',
      worker:get_type(), rspamd_util.get_pid(), table.concat(draws, ','))
end)
