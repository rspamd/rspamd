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

rspamd_config:register_symbol({
  name = 'TEST_CHARTABLE_WORDS',
  type = 'postfilter',
  score = 0.0,
  flags = 'nostat',
  callback = function(task)
    for _, part in ipairs(task:get_text_parts()) do
      for _, word in ipairs(part:get_words('full')) do
        for _, flag in ipairs(word[4]) do
          if flag == 'mixed_script' or flag == 'unicode_spoof' or
              flag == 'confusable_candidate' or flag == 'invisible' or
              flag == 'mixed_numbers' then
            task:insert_result('TEST_CHARTABLE_WORDS', 1.0,
                string.format('%s:%s', word[2], flag))
          end
        end
      end
    end
  end,
})
