-- Several sections set in the global `config` table must all reach the
-- configuration. The nested tables are named after other top level sections:
-- a section must never be read from inside another one.
config.cfgsec_alpha = {
  value = 'alpha',
  cfgsec_beta = { value = 'nested' },
  cfgsec_gamma = { value = 'nested' },
}
config.cfgsec_beta = {
  value = 'beta',
  cfgsec_alpha = { value = 'nested' },
  cfgsec_gamma = { value = 'nested' },
}
config.cfgsec_gamma = {
  value = 'gamma',
  cfgsec_alpha = { value = 'nested' },
  cfgsec_beta = { value = 'nested' },
}

-- A rule for a stock module set the same way
config.regexp = config.regexp or {}
config.regexp.CFGSEC_REGEXP = 'Subject=/./H'

rspamd_config:register_symbol({
  name = 'CFGSEC_SECTIONS',
  score = 1.0,
  callback = function(task)
    for _, name in ipairs({ 'alpha', 'beta', 'gamma' }) do
      local opts = rspamd_config:get_all_opt('cfgsec_' .. name)
      if type(opts) == 'table' then
        task:insert_result('CFGSEC_SECTIONS', 1.0, name .. '=' .. tostring(opts.value))
      else
        task:insert_result('CFGSEC_SECTIONS', 1.0, name .. '=missing')
      end
    end
  end
})
