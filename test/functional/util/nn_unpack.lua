local ucl = require "ucl"

local function unhex(str)
  return (str:gsub('..', function (cc)
    return string.char(tonumber(cc, 16))
  end))
end

local parser = ucl.parser()
local ok, err = parser:parse_string(unhex(arg[1]), 'msgpack')
if not ok then
  io.stderr:write(err)
  os.exit(1)
end

print(ucl.to_format(parser:get_object(), 'json-compact'))
