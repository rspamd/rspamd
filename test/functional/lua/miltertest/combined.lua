-- Combine tests

dofile './lib.lua'
dofile './data.lua'

setup()

local old_setup = setup
local old_teardown = teardown

local empty_function = function() end
setup = empty_function
teardown = empty_function

local function shuffle(tbl)
  local size = #tbl
  for i = size, 1, -1 do
    local rand = math.random(size)
    tbl[i], tbl[rand] = tbl[rand], tbl[i]
  end
  return tbl
end

local files = {'mt1.lua','mt2.lua','mt3.lua','mt4.lua'}
local num_files = #files
for i = 1, num_files do
  table.insert(files, files[i])
end
files = shuffle(files)

for _, f in ipairs(files) do
  dofile(f)
end

old_teardown()
