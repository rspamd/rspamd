local cb = function(task)
  task:insert_result('TOP', 1.0)
end

local cb_dep1 = function(task)
  if task:get_symbol('TOP') then
    task:insert_result('DEP1', 1.0)
  end
end

local cb_gen = function(num)
  local cb_dep = function(task)
    if task:get_symbol('DEP' .. tostring(num)) then
      task:insert_result('DEP' .. tostring(num + 1), 1.0)
    end
  end

  return cb_dep
end

local id = rspamd_config:register_callback_symbol(1.0, cb)
rspamd_config:register_virtual_symbol('TOP', 1.0, id)

rspamd_config:register_symbol('DEP1', 1.0, cb_dep1)
rspamd_config:register_dependency('DEP1', 'TOP')

for i = 2,10 do
  rspamd_config:register_symbol('DEP' .. tostring(i), 1.0, cb_gen(i - 1))
  rspamd_config:register_dependency('DEP' .. tostring(i), 'DEP' .. tostring(i - 1))
end
