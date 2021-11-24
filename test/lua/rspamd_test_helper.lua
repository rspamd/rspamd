local ffi = require "ffi"
local cfg = rspamd_config

ffi.cdef[[
void rspamd_url_init (const char *tld_file);
]]
local exports = {}

function exports.init_url_parser(file)
  if not file then
    local test_dir = string.gsub(debug.getinfo(1).source, "^@(.+/)[^/]+$", "%1")
    file = string.format('%s/unit/%s', test_dir, "test_tld.dat")
  end

  ffi.C.rspamd_url_init(file)
end

function exports.default_config()
  local test_dir = string.gsub(debug.getinfo(1).source, "^@(.+/)[^/]+$", "%1")
  local tld_file = string.format('%s/%s', test_dir, "test_tld.dat")

  local config = {
    options = {
      filters = {'spf', 'dkim', 'regexp'},
      url_tld = tld_file,
      dns = {
        nameserver = {'8.8.8.8'}
      },
    },
    logging = {
      type = 'console',
      level = 'debug'
    },
    metric = {
      name = 'default',
      actions = {
        reject = 100500,
      },
      unknown_weight = 1
    }
  }

  return config
end

return exports