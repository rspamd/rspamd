--[[
Damerau-Levenshtein distance (optimal string alignment variant) over code points.
Faithful port of the engine's distance.ts. Lua 5.1 / LuaJIT compatible.
]]--

local uni = require((...):gsub("%.distance$", "") .. ".unicode")

local M = {}

function M.osa(a_str, b_str)
  local a = uni.codepoints(a_str)
  local b = uni.codepoints(b_str)
  local la, lb = #a, #b
  local d = {}
  for i = 0, la do
    d[i] = {}
    d[i][0] = i
  end
  for j = 0, lb do d[0][j] = j end
  for i = 1, la do
    for j = 1, lb do
      local cost = (a[i] == b[j]) and 0 or 1
      local m = d[i - 1][j] + 1
      local x = d[i][j - 1] + 1
      if x < m then m = x end
      x = d[i - 1][j - 1] + cost
      if x < m then m = x end
      if i > 1 and j > 1 and a[i] == b[j - 1] and a[i - 1] == b[j] then
        x = d[i - 2][j - 2] + 1
        if x < m then m = x end
      end
      d[i][j] = m
    end
  end
  return d[la][lb]
end

return M
