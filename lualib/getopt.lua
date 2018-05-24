local function insert_option(tab, name, value)
  if tab[name] then
    if type(tab[name]) == 'table' then
      table.insert(tab[name], value)
    else
      local old_val = tab[name]
      tab[name] = {
        old_val,
        value
      }
    end
  else
    tab[name] = value
  end
end

local function getopt(arg, options)
  local tab = {}
  for k, v in ipairs(arg) do
    if string.sub(v, 1, 2) == "--" then
      local x = string.find(v, "=", 1, true)
      if x then insert_option(tab, string.sub(v, 3, x - 1), string.sub(v, x + 1))
      else tab[string.sub(v, 3)] = true
      end
    elseif string.sub(v, 1, 1) == "-" then
      local y = 2
      local l = string.len(v)
      local jopt
      while (y <= l) do
        jopt = string.sub(v, y, y)
        if string.find(options, jopt, 1, true) then
          if y < l then
            insert_option(tab, jopt, string.sub(v, y + 1))
            y = l
          else
            insert_option(tab, jopt, arg[k + 1])
          end
        else
          tab[jopt] = true
        end
        y = y + 1
      end
    end
  end
  return tab
end

return {
  getopt = getopt
}
