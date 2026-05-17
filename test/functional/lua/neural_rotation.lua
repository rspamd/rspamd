-- Test helper for the providers-digest rotation scenario.
--
-- Mirrors the SPAM_SYMBOL{i}/HAM_SYMBOL{i} setup from neural.lua (so a Robot
-- suite can drive autolearn via verdict scoring) and adds a callback symbol
-- that forces a symcache-style rotation: mutates the loaded neural rule's
-- settings to flip set.symbols and set.digest in place, then clears
-- set.ann/set.training_profile so the next check_anns poll re-runs profile
-- selection.
--
-- With providers configured + disable_symbols_input=true, the rotation must
-- not invalidate the trained ANN: providers_digest stays constant, so the
-- old profile is still compatible and must be reloaded.

local lua_util = require "lua_util"
local neural_common = require "plugins/neural"

for i = 1, 14 do
  rspamd_config:register_symbol({
    name = 'SPAM_SYMBOL' .. tostring(i),
    score = 5.0,
    callback = function()
      return true, 'Fires always'
    end
  })
  rspamd_config:register_symbol({
    name = 'HAM_SYMBOL' .. tostring(i),
    score = -3.0,
    callback = function()
      return true, 'Fires always'
    end
  })
end

-- Force an in-place "symcache shift" on the loaded neural rule(s).
-- Appends a unique symbol to set.symbols, recomputes set.digest, and clears
-- the loaded ANN reference so the next check_anns poll re-selects a profile
-- from Redis.
--
-- IMPORTANT: registered WITHOUT explicit_disable so it stays subject to the
-- symbols_enabled allowlist — otherwise it would fire on every training scan
-- and trample set.can_store_vectors before training data can accumulate.
-- Replace set.symbols with a wholly fresh list so the Levenshtein distance
-- against the stored profile exceeds the legacy 30% tolerance — pre-fix this
-- would orphan the trained ANN; with providers_digest matching it is still
-- recognised as compatible.
local rotation_counter = 0
rspamd_config.FORCE_ROTATE_NEURAL = {
  callback = function(task)
    rotation_counter = rotation_counter + 1
    for _, rule in pairs(neural_common.settings.rules or {}) do
      for _, set in pairs(rule.settings or {}) do
        if type(set) == 'table' and type(set.symbols) == 'table' then
          local fresh = {}
          for i = 1, math.max(#set.symbols * 2, 32) do
            fresh[#fresh + 1] = string.format('ROTATED_SYM_%d_%d',
              rotation_counter, i)
          end
          table.sort(fresh)
          set.symbols = fresh
          set.digest = lua_util.table_digest(fresh)
          set.ann = nil
          set.training_profile = nil
          -- Leave set.can_store_vectors alone: check_anns has already
          -- populated profile state for this set, the next poll will
          -- reselect from Redis.
        end
      end
    end
    return true, 1.0, string.format('rotated_%d', rotation_counter)
  end
}

dofile(rspamd_env.INSTALLROOT .. "/share/rspamd/rules/controller/init.lua")
