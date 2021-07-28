local lua_selectors = require 'lua_selectors'
local rspamd_text = require 'rspamd_text'

rspamd_config:register_re_selector('test', 'user.lower;header(Subject).lower', ' ')

config['regexp']['LUA_SELECTOR_RE'] = {
  re = 'test=/^test@user\\.com some subject$/{selector}',
  score = 100500,
}

lua_selectors.register_extractor(rspamd_config, 'some_rspamd_text', {
  get_value = function()
    return {rspamd_text.fromstring('hello'), rspamd_text.fromstring('world')}, 'string_list'
  end,
  description = 'Return some rspamd_texts',
})

rspamd_config:register_re_selector('some_rspamd_text_re', 'some_rspamd_text', ' ')

config['regexp']['RSPAMD_TEXT_SELECTOR'] = {
  re = 'some_rspamd_text_re=/^hello$/{selector}',
  score = 1,
}
