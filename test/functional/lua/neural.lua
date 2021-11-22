local logger = require "rspamd_logger"

for i = 1,14 do
  rspamd_config:register_symbol({
    name = 'SPAM_SYMBOL'..tostring(i),
    score = 5.0,
    callback = function()
      return true, 'Fires always'
    end
  })
  rspamd_config:register_symbol({
    name = 'HAM_SYMBOL'..tostring(i),
    score = -3.0,
    callback = function()
      return true, 'Fires always'
    end
  })
end



rspamd_config:register_symbol({
  name = 'NEUTRAL_SYMBOL',
  score = 1.0,
  flags = 'explicit_disable',
  callback = function()
    return true, 'Fires always'
  end
})

rspamd_config.SAVE_NN_ROW = {
  callback = function(task)
    local fname = os.tmpname()
    task:cache_set('nn_row_tmpfile', fname)
    return true, 1.0, fname
  end
}

rspamd_config.SAVE_NN_ROW_IDEMPOTENT = {
  callback = function(task)
    local function tohex(str)
      return (str:gsub('.', function (c)
        return string.format('%02X', string.byte(c))
      end))
    end
    local fname = task:cache_get('nn_row_tmpfile')
    if not fname then
      return
    end
    local f, err = io.open(fname, 'w')
    if not f then
      logger.errx(task, err)
      return
    end
    f:write(tohex(task:cache_get('SHORT_neural_vec_mpack') or ''))
    f:close()
    return
  end,
  type = 'idempotent',
  flags = 'explicit_disable',
  priority = 10,
}

dofile(rspamd_env.INSTALLROOT .. "/share/rspamd/rules/controller/init.lua")
