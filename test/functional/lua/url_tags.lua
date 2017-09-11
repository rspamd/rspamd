
local rspamd_logger = require 'rspamd_logger'

rspamd_config:register_symbol({
  name = 'ADDED_TAGS',
  score = 1.0,
  callback = function(task)
    if not task:get_request_header('addtags') then
      return true, 'nope! not requested'
    end
    local urls = task:get_urls()
    if not (urls and urls[1]) then
      return true, 'nope! found no urls'
    end
    local mpool = task:get_mempool()
    for _, u in ipairs(urls) do
      u:add_tag('test1', 'meta1', mpool)
      u:add_tag('test1', 'meta2', mpool)
      u:add_tag('test2', 'http://www.example.com', mpool)
    end
    return true, 'no worry'
  end
})

rspamd_config:register_symbol({
  name = 'FOUND_TAGS',
  score = 1.0,
  callback = function(task)
    local urls = task:get_urls()
    if not (urls and urls[1]) then
      return true, 'nope! found no urls'
    end
    for _, u in ipairs(urls) do
      local tags = u:get_tags()
      rspamd_logger.debugx(task, 'tags: %1', tags)
      if not tags['test1'] then
        return true, 'no key - test1'
      end
      local found1, found2 = false, false
      for _, e in ipairs(tags['test1']) do
        if e == 'meta1' then found1 = true end
        if e == 'meta2' then found2 = true end
      end
      if not (found1 and found2) then
        return true, 'missing metatags in test1'
      end
      if not tags['test2'] then
        return true, 'no key - test2'
      end
      if not tags['test2'][1] == 'http://www.example.com' then
        return true, 'wrong value in test2 metatag: ' .. tags['test2'][1]
      end
    end
    return true, 'no worry'
  end
})
