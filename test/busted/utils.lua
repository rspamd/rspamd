local path = require 'pl.path'

math.randomseed(os.time())

-- Do not use pl.path.normpath
-- It is broken for paths with leading '../../'
local function normpath(fpath)
  if type(fpath) ~= 'string' then
    error(fpath .. ' is not a string')
  end
  local sep = '/'
  if path.is_windows then
    sep = '\\'
    if fpath:match '^\\\\' then -- UNC
      return '\\\\' .. normpath(fpath:sub(3))
    end
    fpath = fpath:gsub('/','\\')
  end
  local np_gen1, np_gen2 = '([^SEP]+)SEP(%.%.SEP?)', 'SEP+%.?SEP'
  local np_pat1 = np_gen1:gsub('SEP', sep)
  local np_pat2 = np_gen2:gsub('SEP', sep)
  local k
  repeat -- /./ -> /
    fpath, k = fpath:gsub(np_pat2, sep)
  until k == 0
  repeat -- A/../ -> (empty)
    local oldpath = fpath
    fpath, k = fpath:gsub(np_pat1, function(d, up)
      if d == '..' then return nil end
      if d == '.' then return up end
      return ''
    end)
  until k == 0 or oldpath == fpath
  if fpath == '' then fpath = '.' end
  return fpath
end

return {
  split = require 'pl.utils'.split,

  normpath = normpath,

  shuffle = function(t, seed)
    if seed then math.randomseed(seed) end
    local n = #t
    while n >= 2 do
      local k = math.random(n)
      t[n], t[k] = t[k], t[n]
      n = n - 1
    end
    return t
  end
}
