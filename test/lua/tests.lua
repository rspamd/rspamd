-- Run all unit tests in 'unit' directory

local telescope = require "telescope"
require "rspamd_assertions"
local loaded, luacov = pcall(require, 'luacov.runner')
if not loaded then
  luacov = {
    init = function() end,
    shutdown = function() end,
    run_report = function() end
  }
end
luacov.init()

local contexts = {}

for _,t in ipairs(tests_list) do
  telescope.load_contexts(t, contexts)
end
local function test_filter(test)
  return test.name:match(test_pattern)
end
if not test_pattern then
  test_filter = function(_) return true end
end

local buffer = {}
local results = telescope.run(contexts, callbacks, test_filter)
local summary, data = telescope.summary_report(contexts, results)

table.insert(buffer, telescope.test_report(contexts, results))
table.insert(buffer, summary)

local report = telescope.error_report(contexts, results)

if report then
  table.insert(buffer, "")
  table.insert(buffer, report)
end

if #buffer > 0 then print(table.concat(buffer, "\n")) end

for _, v in pairs(results) do
  if v.status_code == telescope.status_codes.err or
    v.status_code == telescope.status_codes.fail then
    os.exit(1)
  end
end

luacov:shutdown()
luacov:run_report()
