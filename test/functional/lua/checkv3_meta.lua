-- Symbols exercising the /checkv3 custom-metadata feature.
--
-- Option A: a custom field carried in the metadata "headers" sub-object is
--           exposed as a task request header (task:get_request_header).
-- Option B: arbitrary metadata fields are readable via task:get_metadata()
--           and task:get_metadata_field(key).
--
-- All callbacks are no-ops unless their specific field is present, so the
-- symbols stay inert for every other suite sharing the merged config.

rspamd_config:register_symbol({
  name = 'TEST_V3_META_HEADER',
  score = 1.0,
  callback = function(task)
    local h = task:get_request_header('X-V3-Custom')
    if not h then return end
    return true, tostring(h)
  end
})

rspamd_config:register_symbol({
  name = 'TEST_V3_META_FIELD',
  score = 1.0,
  callback = function(task)
    local meta = task:get_metadata()
    if not meta or not meta.custom_field then return end
    return true, tostring(meta.custom_field)
  end
})

rspamd_config:register_symbol({
  name = 'TEST_V3_META_FIELD_LOOKUP',
  score = 1.0,
  callback = function(task)
    local v = task:get_metadata_field('custom_field')
    if not v then return end
    return true, tostring(v)
  end
})
