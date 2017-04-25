codes = true
std = 'min'

exclude_files = {
  '/**/contrib/**',
  '/**/test/lua/**',
}

globals = {
  'check_header_delimiter_empty',
  'check_header_delimiter_tab',
  'classifiers',
  'config',
  'confighelp',
  'kmail_msgid',
  'rspamd_classifiers',
  'rspamd_config',
  'rspamd_count_metatokens',
  'rspamd_gen_metatokens',
  'rspamd_parse_redis_server',
  'rspamd_paths',
  'rspamd_plugins',
  'rspamd_redis_make_request',
  'rspamd_str_split',
  'rspamd_version',
  'rspamd_map_add',
}

ignore = {
  '212', -- unused argument
  '612', -- trailing whitespace
  '631', -- line is too long
}

files['/**/src/plugins/lua/spamassassin.lua'].globals = {
  'ffi',
  'jit',
}

files['/**/src/plugins/lua/greylist.lua'].globals = {
  'math.ifloor',
}

files['/**/src/rspamadm/*'].globals = {
  'ansicolors',
  'getopt',
}
