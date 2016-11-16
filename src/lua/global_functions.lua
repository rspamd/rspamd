local logger = require "rspamd_logger"

-- This function parses redis server definition using either
-- specific server string for this module or global
-- redis section
function rspamd_parse_redis_server(module_name)

  local default_port = 6379
  local default_timeout = 1.0
  local upstream_list = require "rspamd_upstream_list"

  local function try_load_redis_servers(options)
    -- Try to get read servers:
    local upstreams_read, upstreams_write

    if options['read_servers'] then
      upstreams_read = upstream_list.create(rspamd_config,
        options['read_servers'], default_port)
    elseif options['servers'] then
      upstreams_read = upstream_list.create(rspamd_config,
        options['servers'], default_port)
    elseif options['server'] then
      upstreams_read = upstream_list.create(rspamd_config,
        options['server'], default_port)
    end

    if upstreams_read then
      if options['write_servers'] then
        upstreams_write = upstream_list.create(rspamd_config,
          options['write_servers'], default_port)
      else
        upstreams_write = upstreams_read
      end
    end

    if upstreams_write and upstreams_read then
      local ret = {
        read_servers = upstreams_read,
        write_servers = upstreams_write,
      }
      ret['timeout'] = default_timeout
      if options['timeout'] then
        ret['timeout'] = tonumber(options['timeout'])
      end
      if options['prefix'] then
        ret['prefix'] = options['prefix']
      end
      if options['db'] then
        ret['db'] = options['db']
      elseif options['dbname'] then
        ret['db'] = options['dbname']
      end
      if options['password'] then
        ret['password'] = options['password']
      end
      return ret
    end

    return nil
  end

  local opts = rspamd_config:get_all_opt(module_name)
  local ret

  if opts then
    ret = try_load_redis_servers(opts)
  end

  if ret then
    return ret
  end

  opts = rspamd_config:get_all_opt('redis')

  if opts then
    if opts[module_name] then
      ret = try_load_redis_servers(opts[module_name])
      if ret then
        return ret
      end
    else
      ret = try_load_redis_servers(opts)

      if opts['disabled_modules'] then
        for _,v in ipairs(opts['disabled_modules']) do
          if v == module_name then
            logger.infox(rspamd_config, "NOT using default redis server for module %s: it is disabled",
              module_name)

              return nil
          end
        end
      end

      if ret then
        logger.infox(rspamd_config, "using default redis server for module %s",
          module_name)
      end
    end
  end

  return ret
end

-- Performs async call to redis hiding all complexity inside function
-- task - rspamd_task
-- redis_params - valid params returned by rspamd_parse_redis_server
-- key - key to select upstream or nil to select round-robin/master-slave
-- is_write - true if need to write to redis server
-- callback - function to be called upon request is completed
-- command - redis command
-- args - table of arguments
function rspamd_redis_make_request(task, redis_params, key, is_write, callback, command, args)
  local addr
  local function rspamd_redis_make_request_cb(err, data)
    if err then
      addr:fail()
    else
      addr:ok()
    end
    callback(err, data, addr)
  end
  if not task or not redis_params or not callback or not command then
    return false,nil,nil
  end

  local rspamd_redis = require "rspamd_redis"

  if key then
    if is_write then
      addr = redis_params['write_servers']:get_upstream_by_hash(key)
    else
      addr = redis_params['read_servers']:get_upstream_by_hash(key)
    end
  else
    if is_write then
      addr = redis_params['write_servers']:get_upstream_master_slave(key)
    else
      addr = redis_params['read_servers']:get_upstream_round_robin(key)
    end
  end

  if not addr then
    logger.errx(task, 'cannot select server to make redis request')
  end

  local options = {
    task = task,
    callback = rspamd_redis_make_request_cb,
    host = addr:get_addr(),
    timeout = redis_params['timeout'],
    cmd = command,
    args = args
  }

  if redis_params['password'] then
    options['password'] = redis_params['password']
  end

  if redis_params['db'] then
    options['dbname'] = redis_params['db']
  end

  local ret,conn = rspamd_redis.make_request(options)
  return ret,conn,addr
end

function rspamd_str_split(s, sep)
  local lpeg = require "lpeg"
  sep = lpeg.P(sep)
  local elem = lpeg.C((1 - sep)^0)
  local p = lpeg.Ct(elem * (sep * elem)^0)   -- make a table capture
  return lpeg.match(p, s)
end

-- Metafunctions
local function meta_size_function(task)
  local sizes = {
    100,
    200,
    500,
    1000,
    2000,
    4000,
    10000,
    20000,
    30000,
    100000,
    200000,
    400000,
    800000,
    1000000,
    2000000,
    8000000,
  }

  local size = task:get_size()
  for i = 1,#sizes do
    if sizes[i] >= size then
      return {i / #sizes}
    end
  end

  return {0}
end

local function meta_images_function(task)
  local images = task:get_images()
  local ntotal = 0
  local njpg = 0
  local npng = 0
  local nlarge = 0
  local nsmall = 0

  if images then
    for _,img in ipairs(images) do
      if img:get_type() == 'png' then
        npng = npng + 1
      elseif img:get_type() == 'jpeg' then
        njpg = njpg + 1
      end

      local w = img:get_width()
      local h = img:get_height()

      if w > 0 and h > 0 then
        if w + h > 256 then
          nlarge = nlarge + 1
        else
          nsmall = nsmall + 1
        end
      end

      ntotal = ntotal + 1
    end
  end
  if ntotal > 0 then
    njpg = njpg / ntotal
    npng = npng / ntotal
    nlarge = nlarge / ntotal
    nsmall = nsmall / ntotal
  end
  return {ntotal,njpg,npng,nlarge,nsmall}
end

local function meta_nparts_function(task)
  local nattachments = 0
  local ntextparts = 0
  local totalparts = 1

  local tp = task:get_text_parts()
  if tp then
    ntextparts = #tp
  end

  local parts = task:get_parts()

  if parts then
    for _,p in ipairs(parts) do
      if p:get_filename() then
        nattachments = nattachments + 1
      end
      totalparts = totalparts + 1
    end
  end

  return {ntextparts/totalparts, nattachments/totalparts}
end

local function meta_encoding_function(task)
  local nutf = 0
  local nother = 0

  local tp = task:get_text_parts()
  if tp then
    for _,p in ipairs(tp) do
      if p:is_utf() then
        nutf = nutf + 1
      else
        nother = nother + 1
      end
    end
  end

  return {nutf, nother}
end

local function meta_recipients_function(task)
  local nmime = 0
  local nsmtp = 0

  if task:has_recipients('mime') then
    nmime = #(task:get_recipients('mime'))
  end
  if task:has_recipients('smtp') then
    nsmtp = #(task:get_recipients('smtp'))
  end

  if nmime > 0 then nmime = 1.0 / nmime end
  if nsmtp > 0 then nsmtp = 1.0 / nsmtp end

  return {nmime,nsmtp}
end

local function meta_received_function(task)
  local ret = 0
  local rh = task:get_received_headers()

  if rh and #rh > 0 then
    ret = 1 / #rh
  end

  return {ret}
end

local function meta_urls_function(task)
  if task:has_urls() then
    return {1.0 / #(task:get_urls())}
  end

  return {0}
end

local metafunctions = {
  {
    cb = meta_size_function,
    ninputs = 1,
  },
  {
    cb = meta_images_function,
    ninputs = 5,
    -- 1 - number of images,
    -- 2 - number of png images,
    -- 3 - number of jpeg images
    -- 4 - number of large images (> 128 x 128)
    -- 5 - number of small images (< 128 x 128)
  },
  {
    cb = meta_nparts_function,
    ninputs = 2,
    -- 1 - number of text parts
    -- 2 - number of attachments
  },
  {
    cb = meta_encoding_function,
    ninputs = 2,
    -- 1 - number of utf parts
    -- 2 - number of non-utf parts
  },
  {
    cb = meta_recipients_function,
    ninputs = 2,
    -- 1 - number of mime rcpt
    -- 2 - number of smtp rcpt
  },
  {
    cb = meta_received_function,
    ninputs = 1,
  },
  {
    cb = meta_urls_function,
    ninputs = 1,
  },
}

function rspamd_gen_metatokens(task)
  local ipairs = ipairs
  local metatokens = {}
  for _,mt in ipairs(metafunctions) do
    local ct = mt.cb(task)

    for _,tok in ipairs(ct) do
      table.insert(metatokens, tok)
    end
  end

  return metatokens
end

function rspamd_count_metatokens()
  local ipairs = ipairs
  local total = 0
  for _,mt in ipairs(metafunctions) do
    total = total + mt.ninputs
  end

  return total
end
