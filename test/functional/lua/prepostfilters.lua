for i = 1,10 do
  local name = string.format('DEP_TEST%d', i)
  local dep_name = string.format('DEP_TEST%d', i - 1)
  rspamd_config:register_symbol({
    type = 'normal',
    name = name,
    callback = function(task)
      local function dns_cb()
        if i ~= 1 then
          if task:has_symbol(dep_name) then
            task:insert_result(name, 1.0)
          end
        else
          task:insert_result(name, 1.0)
        end
      end
      if task:has_symbol('TEST_PRE') then
        local r = task:get_resolver()
        r:resolve_a({task = task, name = 'example.com', callback = dns_cb})
      end
    end
  })

  if i ~= 1 then
    rspamd_config:register_dependency(name, dep_name)
  end

  rspamd_config:set_metric_symbol({
    name = name,
    score = 1.0
  })
end


rspamd_config:register_symbol({
  type = 'postfilter',
  name = 'TEST_POST',
  callback = function(task)
    for i = 1,10 do
      local name = string.format('DEP_TEST%d', i)
      if not task:has_symbol(name) then
        return
      end
    end
    if task:has_symbol('TEST_PRE') then
      task:insert_result('TEST_POST', 1.0)
    end
  end
})
rspamd_config:set_metric_symbol({
  name = 'TEST_POST',
  score = 1.0
})

rspamd_config:register_symbol({
  type = 'prefilter',
  name = 'TEST_PRE',
  callback = function(task)
    task:insert_result('TEST_PRE', 1.0)
  end
})
rspamd_config:set_metric_symbol({
  name = 'TEST_PRE',
  score = 1.0
})
