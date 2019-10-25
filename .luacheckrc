codes = true
std = 'min'

exclude_files = {
  '/**/contrib/**',
  '/**/test/lua/**',
  '/**/test/functional/lua/miltertest/**',
  '/**/test/functional/lua/rspamadm/**',
  '.git/**/',
}

globals = {
  'check_header_delimiter_empty',
  'check_header_delimiter_tab',
  'classifiers',
  'config',
  'confighelp',
  'rspamd_classifiers',
  'rspamd_config',
  'rspamd_count_metatokens',
  'rspamd_gen_metatokens',
  'rspamd_parse_redis_server',
  'rspamd_paths',
  'rspamd_env',
  'rspamd_plugins',
  'rspamd_redis_make_request',
  'rspamd_str_split',
  'rspamd_version',
  'rspamd_map_add',
  'rspamd_maps',
  'rspamd_plugins_state',
  'rspamadm',
  'loadstring',
  'rspamadm_ev_base',
  'rspamadm_session',
  'rspamadm_dns_resolver',
  'jit'
}

ignore = {
  '212', -- unused argument
  '612', -- trailing whitespace
  '311', -- value assigned to variable X is unused
}

files['/**/src/plugins/lua/spamassassin.lua'].globals = {
  'ffi',
  'jit',
}

files['/**/src/plugins/lua/greylist.lua'].globals = {
  'math.ifloor',
}
files['/**/src/plugins/lua/reputation.lua'].globals = {
  'math.tanh',
}

files['/**/lualib/lua_util.lua'].globals = {
  'table.unpack',
  'unpack',
}

files['/**/lualib/lua_redis.lua'].globals = {
  'rspamadm_ev_base',
}

files['/**/src/rspamadm/*'].globals = {
  'ansicolors',
  'getopt',
}

files['test/functional/lua/test_coverage.lua'].globals = {
  '__GLOBAL_COVERAGE_WATCHDOG'
}

files['/**/rules/'].ignore = {'631'}
files['/**/test/functional/'].ignore = {'631'}

max_string_line_length = 500
max_comment_line_length = 500
