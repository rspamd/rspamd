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

-- The 'orig' flavour must be reachable through selectors and return the
-- address as it was seen in the message, before any task:set_from rewrite
local selector_from = lua_selectors.create_selector_closure(
    rspamd_config, "from('mime'):addr", '')
local selector_from_orig = lua_selectors.create_selector_closure(
    rspamd_config, "from('mime', 'orig'):addr", '')

rspamd_config:register_symbol({
  name = 'SELECTOR_FROM_ORIG',
  score = 1.0,
  callback = function(task)
    local cur = selector_from(task)
    local orig = selector_from_orig(task)
    return true, string.format('%s|%s', cur or 'nil', orig or 'nil')
  end
})
