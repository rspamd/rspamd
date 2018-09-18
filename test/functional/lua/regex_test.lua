local function get_urls(task)
  local urls = task:get_urls()
  for _, u in ipairs(urls) do
    task:insert_result('FOUND_URL', 1.0, tostring(u))
  end
end

rspamd_config:register_symbol({
  name = 'SIMPLE',
  score = 1.0,
  callback = get_urls
})
