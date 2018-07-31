context("Lua util - extract_specific_urls", function()
  local util  = require 'lua_util'
  local mpool = require "rspamd_mempool"
  local fun   = require "fun"
  local url   = require "rspamd_url"
  local logger = require "rspamd_logger"
  local ffi = require "ffi"
  local rspamd_util = require "rspamd_util"
  local rspamd_task = require "rspamd_task"

  ffi.cdef[[
  void rspamd_url_init (const char *tld_file);
  unsigned ottery_rand_range(unsigned top);
  void rspamd_http_normalize_path_inplace(char *path, size_t len, size_t *nlen);
  ]]

  local test_dir = string.gsub(debug.getinfo(1).source, "^@(.+/)[^/]+$", "%1")

  ffi.C.rspamd_url_init(string.format('%s/%s', test_dir, "test_tld.dat"))

  local task_object = {
    urls      = {},
    cache_set = function(self, ...) end,
    cache_get = function(self, ...) end,
    get_urls  = function(self, need_emails) return self.urls end
  }

  local url_list = {
    "google.com",
    "mail.com",
    "bizz.com",
    "bing.com",
    "example.com",
    "gov.co.net",
    "tesco.co.net",
    "domain1.co.net",
    "domain2.co.net",
    "domain3.co.net",
    "domain4.co.net",
    "abc.org",
    "icq.org",
    "meet.org",
    "domain1.org",
    "domain2.org",
    "domain3.org",
    "domain3.org",
    "test.com",
  }

  local cases = {
    {expect = url_list, filter = nil, limit = 9999, need_emails = true, prefix = 'p'},
    {expect = {}, filter = (function() return false end), limit = 9999, need_emails = true, prefix = 'p'},
    {expect = {"domain4.co.net", "test.com"}, filter = nil, limit = 2, need_emails = true, prefix = 'p'},
    {
      expect = {"gov.co.net", "tesco.co.net", "domain1.co.net", "domain2.co.net", "domain3.co.net", "domain4.co.net"},
      filter = (function(s) return s:get_host():sub(-4) == ".net" end),
      limit = 9999,
      need_emails = true,
      prefix = 'p'
    },
    {
      input  = {"a.google.com", "b.google.com", "c.google.com", "a.net", "bb.net", "a.bb.net", "b.bb.net"},
      expect = {"a.bb.net", "b.google.com", "a.net", "bb.net", "a.google.com"},
      filter = nil,
      limit = 9999,
      esld_limit = 2,
      need_emails = true,
      prefix = 'p'
    },
    {
      input  = {"abc@a.google.com", "b.google.com", "c.google.com", "a.net", "bb.net", "a.bb.net", "b.bb.net"},
      expect = {"abc@a.google.com", "a.bb.net", "b.google.com", "a.net", "bb.net", "abc@a.google.com"},
      filter = nil,
      limit = 9999,
      esld_limit = 2,
      need_emails = true,
      prefix = 'p'
    }
  }

  local function prepare_actual_result(actual)
    return fun.totable(fun.map(
      function(u) return u:get_raw():gsub('^%w+://', '') end,
      actual
    ))
  end

  local pool = mpool.create()

  for i,c in ipairs(cases) do

    local function prepare_url_list(c)
      return fun.totable(fun.map(
    function (u) return url.create(pool, u) end,
    c.input or url_list
    ))
  end

    test("extract_specific_urls, backward compatibility case #" .. i, function()
      task_object.urls = prepare_url_list(c)
      if (c.esld_limit) then
        -- not awailable in deprecated version
        return
      end
      local actual = util.extract_specific_urls(task_object, c.limit, c.need_emails, c.filter, c.prefix)

      local actual_result = prepare_actual_result(actual)

      --[[
        local s = logger.slog("%1 =?= %2", c.expect, actual_result)
        print(s) --]]

      assert_equal(true, util.table_cmp(c.expect, actual_result), "checking that we got the same tables")

    end)

    test("extract_specific_urls " .. i, function()
      task_object.urls = prepare_url_list(c)

      local actual = util.extract_specific_urls({
        task = task_object,
        limit = c.limit,
        esld_limit = c.esld_limit,
        need_emails = c.need_emails,
        filter = c.filter,
        prefix = c.prefix,
      })

      local actual_result = prepare_actual_result(actual)

      --[[
        local s = logger.slog("case[%1] %2 =?= %3", i, c.expect, actual_result)
        print(s) --]]

      assert_equal(true, util.table_cmp(c.expect, actual_result), "checking that we got the same tables")

    end)
  end

--[[ ******************* kinda functional *************************************** ]]
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

  test("extract_specific_urls - from email", function()
    local cfg = rspamd_util.config_from_ucl(config, "INIT_URL,INIT_LIBS,INIT_SYMCACHE,INIT_VALIDATE,INIT_PRELOAD_MAPS")
    assert_not_nil(cfg)

    local msg = [[
From: <>
To: <nobody@example.com>
Subject: test
Content-Type: multipart/alternative;
    boundary="_000_6be055295eab48a5af7ad4022f33e2d0_"

--_000_6be055295eab48a5af7ad4022f33e2d0_
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: base64

Hello world


--_000_6be055295eab48a5af7ad4022f33e2d0_
Content-Type: text/html; charset="utf-8"

<html><body>
<a href="http://example.net">http://example.net</a>
<a href="http://example1.net">http://example1.net</a>
<a href="http://example2.net">http://example2.net</a>
<a href="http://example3.net">http://example3.net</a>
<a href="http://example4.net">http://example4.net</a>
<a href="http://domain1.com">http://domain1.com</a>
<a href="http://domain2.com">http://domain2.com</a>
<a href="http://domain3.com">http://domain3.com</a>
<a href="http://domain4.com">http://domain4.com</a>
<a href="http://domain5.com">http://domain5.com</a>
<a href="http://domain.com">http://example.net/</a>
</html>
]]
    local expect = {"example.net", "domain.com"}
    local res,task = rspamd_task.load_from_string(msg, rspamd_config)

    if not res then
      assert_true(false, "failed to load message")
    end

    if not task:process_message() then
      assert_true(false, "failed to process message")
    end

    local actual = util.extract_specific_urls({
      task = task,
      limit = 2,
      esld_limit = 2,
    })

    local actual_result = prepare_actual_result(actual)

    --[[
      local s = logger.slog("case[%1] %2 =?= %3", i, expect, actual_result)
      print(s) --]]

    assert_equal("domain.com", actual_result[1], "checking that first url is the one with highest suspiciousness level")

  end)
end)