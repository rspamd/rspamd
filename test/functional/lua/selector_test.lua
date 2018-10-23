rspamd_config:register_re_selector('test', 'user.lower;header(Subject).lower', ' ')

config['regexp']['LUA_SELECTOR_RE'] = {
  re = 'test=/^test@user\\.com some subject$/{selector}',
  score = 100500,
}
