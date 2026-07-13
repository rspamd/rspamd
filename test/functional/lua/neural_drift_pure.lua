-- Test helper for the pure-symbols drift scenario.
--
-- Drives is_profile_compatible's symbol-list threshold in pure-symbols
-- mode (no providers configured). The threshold was raised from 30% to
-- 50%; this helper exercises both sides of that line:
-- FORCE_DRIFT_NEURAL_40 produces a 40%-drift set (must stay compatible),
-- FORCE_DRIFT_NEURAL_60 produces a 60%-drift set (must be rejected).
--
-- distance_sorted is an asymmetric edit-distance walk: when the fresh
-- entries sort to one end of the list (here, before every baseline
-- name, since "DRIFT_*" < "FORCE_*" < "HAM_*" < "SPAM_*") and the dropped
-- entries are at the other end, the function reports dist ≈ replace_k
-- (not 2*replace_k). So to hit dist == drift_pct% of n we drop and add
-- k = drift_pct * n / 100 entries, not / 200.

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

-- Per-(rule, set) baseline snapshot, captured on the first drift call so
-- subsequent calls compare against the originally-trained symbol list and
-- not against a previously-drifted one.
local baselines = {}

local function snapshot_key(rule, set)
  return tostring(rule.prefix or rule.name or rule) .. ':' ..
      tostring(set.name or 'default')
end

local function apply_drift(drift_pct)
  for _, rule in pairs(neural_common.settings.rules or {}) do
    for _, set in pairs(rule.settings or {}) do
      if type(set) == 'table' and type(set.symbols) == 'table' then
        local key = snapshot_key(rule, set)
        if not baselines[key] then
          local snap = {}
          for i, s in ipairs(set.symbols) do snap[i] = s end
          baselines[key] = snap
        end
        local base = baselines[key]
        local n = #base
        local replace = math.floor(drift_pct * n / 100 + 0.5)
        if replace < 1 then replace = 1 end
        if replace > n then replace = n end
        local result = {}
        for i = 1, n - replace do result[i] = base[i] end
        for i = 1, replace do
          result[#result + 1] = string.format('DRIFT_NEW_SYM_%d_%d',
            drift_pct, i)
        end
        table.sort(result)
        set.symbols = result
        set.digest = lua_util.table_digest(result)
        -- Clear loaded ANN + training_profile so the next check_anns poll
        -- re-runs profile selection against the freshly-drifted symbol list.
        set.ann = nil
        set.training_profile = nil
      end
    end
  end
end

-- Both drift callbacks are registered WITHOUT explicit_disable so they stay
-- subject to the symbols_enabled allowlist -- otherwise they would fire on
-- every training scan and trample set state before training data accumulates.
rspamd_config.FORCE_DRIFT_NEURAL_40 = {
  callback = function()
    apply_drift(40)
    return true, 1.0, 'drift_40'
  end
}

rspamd_config.FORCE_DRIFT_NEURAL_60 = {
  callback = function()
    apply_drift(60)
    return true, 1.0, 'drift_60'
  end
}

dofile(rspamd_env.INSTALLROOT .. "/share/rspamd/rules/controller/init.lua")
