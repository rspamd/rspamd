-- Run all unit tests in 'unit' directory

local telescope = require "telescope"

local contexts = {}

for _,t in ipairs(tests_list) do
  telescope.load_contexts(t, contexts)
end
local buffer = {}
local results = telescope.run(contexts, callbacks, test_pattern)
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