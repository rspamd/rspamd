local rspamd_text = require 'rspamd_text'

-- Unflattened selectors hand rspamd_text rather than Lua strings to the rbl
-- plugin; expose the helo that way for the RBL_NOIP_SELECTOR_TEXT rule
rspamd_config:register_symbol({
  name = 'RBL_NOIP_HELO_TEXT',
  type = 'prefilter',
  priority = 10,
  callback = function(task)
    local helo = task:get_helo()
    if helo then
      task:cache_set('rbl_noip_helo_text', rspamd_text.fromstring(helo))
    end
  end,
})
