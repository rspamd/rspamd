local logger = require "rspamd_logger"
local util = require "rspamd_util"

local function save_message(task)
  base = rspamd_config:get_module_opt('save_rejected', 'base_path')
  filename = string.format("%d.R%s.%s", os.time(), util.random_hex(16), util.get_hostname())
  path = base .. '/' .. filename

  logger.infox(task, "Saving rejected message %s to %s", task:get_message_id(), path)

  file = io.open(path, 'w')

  if not file then
    logger.errx("Cannot open file %s for writing!", file)
    return
  end

  file:write(tostring(task:get_raw_headers()))
  file:write(tostring(task:get_rawbody()))
  file:close()
end

local function check_action(task)
  if rspamd_config:get_module_opt('save_rejected', 'enabled') then
    if task:get_metric_result()['action'] == 'reject' then
      return true
    end
  end
  return false
end

rspamd_config:register_symbol({
  name = 'SAVE_REJECTED_MESSAGE',
  type = 'idempotent',
  flags = 'ignore_passthrough',
  condition = check_action,
  callback = save_message
})
