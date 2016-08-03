rspamd_config:register_post_filter(function(task)
  task:set_pre_result('soft reject', 'Pre Result Set')
end)
