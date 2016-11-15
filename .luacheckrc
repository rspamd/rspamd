codes = true
std = 'min'

exclude_files = {
}

globals = {
  'classifiers',
  'config',
  'rspamd_config',
  'rspamd_count_metatokens',
  'rspamd_gen_metatokens',
  'rspamd_parse_redis_server',
  'rspamd_paths',
  'rspamd_plugins',
  'rspamd_redis_make_request',
  'rspamd_str_split',
  'rspamd_version',
}

ignore = {
}

files['/**/rules/regexp/headers.lua'].globals = {
  'check_header_delimiter_empty',
  'check_header_delimiter_tab',
  'kmail_msgid',
}

files['/**/src/plugins/lua/spamassassin.lua'].globals = {
  'ffi',
  'jit',
}
