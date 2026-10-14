-- Probes for the force_actions tests, each one triggered by a symbol that the
-- settings of the test insert
local lua_util = require "lua_util"

-- A postfilter at the medium priority, where e.g. greylisting acts on the
-- selected action: it records the action it sees
rspamd_config:register_symbol({
  name = 'FA_ACTION_PROBE',
  type = 'postfilter',
  priority = lua_util.symbols_priorities.medium,
  flags = 'empty,ignore_passthrough',
  score = 0.0,
  callback = function(task)
    if task:has_symbol('FA_PROBE_ACTION') then
      return true, task:get_metric_action()
    end
  end,
})

-- A least result of another module at the default (normal) priority, as DMARC
-- sets it; a postfilter, so that it is recorded after the force_actions rule
rspamd_config:register_symbol({
  name = 'FA_LEAST_PROBE',
  type = 'postfilter',
  flags = 'empty,ignore_passthrough',
  score = 0.0,
  callback = function(task)
    if task:has_symbol('FA_PROBE_LEAST') then
      task:set_pre_result('reject', 'Rejected by the least probe', 'fa_probe', nil, nil, 'least')
      return true
    end
  end,
})

-- A least result of another module heading the list, above the result that
-- selects the action
rspamd_config:register_symbol({
  name = 'FA_LEAST_HEAD_PROBE',
  flags = 'empty',
  score = 0.0,
  callback = function(task)
    if task:has_symbol('FA_PROBE_LEAST_HEAD') then
      task:set_pre_result('add header', 'Least head', 'fa_probe', nil, nil, 'least')
      return true
    end
  end,
})

-- A main stage result with a reply that is not for the SMTP client
rspamd_config:register_symbol({
  name = 'FA_NOTE_PROBE',
  flags = 'empty',
  score = 0.0,
  callback = function(task)
    if task:has_symbol('FA_PROBE_NOTE') then
      task:set_pre_result { action = 'reject', message = 'Internal note', module = 'fa_probe',
                            flags = 'no_smtp_message,process_all', priority = 0 }
      return true
    end
  end,
})

-- Sets a pre-result with several flags and reads it back
rspamd_config:register_symbol({
  name = 'FA_PRE_RESULT_PROBE',
  type = 'postfilter',
  flags = 'empty,ignore_passthrough',
  score = 0.0,
  callback = function(task)
    if task:has_symbol('FA_PROBE_PRE_RESULT') then
      task:set_pre_result { action = 'fa_hold', message = 'Internal note', module = 'fa_probe',
                            flags = 'least,no_smtp_message' }
      local _, action, message, module, flags = task:has_pre_result()
      return true, action, message, module, flags
    end
  end,
})

-- A postfilter at the medium priority that stops on a passthrough result, as
-- e.g. greylisting does
rspamd_config:register_symbol({
  name = 'FA_STOPPED_PROBE',
  type = 'postfilter',
  priority = lua_util.symbols_priorities.medium,
  flags = 'empty',
  score = 0.0,
  callback = function(task)
    if task:has_symbol('FA_PROBE_STOPPED') then
      return true
    end
  end,
})

-- Another module rejects with a reply for the SMTP client, at the low priority
rspamd_config:register_symbol({
  name = 'FA_REPLY_PROBE',
  type = 'prefilter',
  flags = 'empty,ignore_passthrough',
  score = 0.0,
  callback = function(task)
    if task:has_symbol('FA_PROBE_REPLY') then
      task:set_pre_result { action = 'reject', message = 'Rejected by the probe', module = 'fa_probe',
                            flags = 'process_all', priority = 0 }
      return true
    end
  end,
})
