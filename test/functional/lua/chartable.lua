rspamd_config:register_symbol({
  name = 'TEST_LANGUAGE',
  type = 'postfilter',
  score = 0.0,
  flags = 'nostat',
  callback = function(task)
    for _, part in ipairs(task:get_text_parts()) do
      local language = part:get_language()

      if language then
        task:insert_result('TEST_LANGUAGE', 1.0, language)
      end
    end
  end,
})
