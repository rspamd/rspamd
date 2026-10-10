require('global_functions')()

for _, plugin in ipairs({ 'history_redis', 'metadata_exporter', 'clickhouse' }) do
  dofile(rspamd_paths.PLUGINSDIR .. '/' .. plugin .. '.lua')
end
