local rspamd_dns = require "rspamd_dns"
local logger = require "rspamd_logger"

local _r,err = rspamd_config:load_ucl('/Users/mgalanin/build/robot-save/rspamd.conf.last')

if not _r then
  rspamd_logger.errx('cannot parse %s: %s', opts['config'], err)
  os.exit(1)
end

_r,err = rspamd_config:parse_rcl({'logging', 'worker'})
if not _r then
  rspamd_logger.errx('cannot process %s: %s', opts['config'], err)
  os.exit(1)
end

rspamd_config:init_subsystem('dns', rspamadm_ev_base)


local is_ok, results = rspamd_dns.request({
     config = rspamd_config,
     session = rspamadm_session,

     type = 'txt',
     name = 'test._domainkey.example.com',
     -- name = '_dmarc.google.com',
   })

print(is_ok, results[1])
