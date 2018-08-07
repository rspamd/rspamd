-- inet addr tests

context("Received headers parser", function()
  local ffi = require("ffi")

  ffi.cdef[[
    struct received_header {
    char *from_hostname;
    char *from_ip;
    char *real_hostname;
    char *real_ip;
    char *by_hostname;
    char *for_mbox;
    void *addr;
    void *hdr;
    long timestamp;
    int type;
    int flags;
  };
  struct rspamd_task * rspamd_task_new(struct rspamd_worker *worker, struct rspamd_config *cfg);
  int rspamd_smtp_received_parse (struct rspamd_task *task,
    const char *data, size_t len, struct received_header *rh);
  ]]

  local cases = {
    {[[from out-9.smtp.github.com (out-9.smtp.github.com [192.30.254.192])
 (using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
 (No client certificate requested)
 by mail.highsecure.ru (Postfix) with ESMTPS id C7B1A30014A
 for <xxx@xxx.xxx>; Tue,  3 Jul 2018 14:40:19 +0200 (CEST)]],
     {
       from_hostname = 'out-9.smtp.github.com',
       from_ip = '192.30.254.192',
       real_ip = '192.30.254.192',
       by_hostname = 'mail.highsecure.ru',
     }
    },
    {[[from localhost ([127.0.0.1]:49019 helo=hummus.csx.cam.ac.uk)
 by hummus.csx.cam.ac.uk with esmtp (Exim 4.91-pdpfix1)
 (envelope-from <exim-dev-bounces@exim.org>)
 id 1fZ55o-0006DP-3H
 for <xxx@xxx.xxx>; Sat, 30 Jun 2018 02:54:28 +0100]],
     {
       from_hostname = 'localhost',
       from_ip = '127.0.0.1',
       real_ip = '127.0.0.1',
       by_hostname = 'hummus.csx.cam.ac.uk',
     }
    },
    {[[from smtp.spodhuis.org ([2a02:898:31:0:48:4558:736d:7470]:38689
 helo=mx.spodhuis.org)
 by hummus.csx.cam.ac.uk with esmtpsa (TLSv1.3:TLS_AES_256_GCM_SHA384:256)
 (Exim 4.91-pdpfix1+cc) (envelope-from <xxx@exim.org>)
 id 1fZ55k-0006CO-9M
 for exim-dev@exim.org; Sat, 30 Jun 2018 02:54:24 +0100]],
     {
       from_hostname = 'smtp.spodhuis.org',
       from_ip = '2a02:898:31:0:48:4558:736d:7470',
       real_ip = '2a02:898:31:0:48:4558:736d:7470',
       by_hostname = 'hummus.csx.cam.ac.uk',
     }
    },
    {'from aaa.cn ([1.1.1.1]) by localhost.localdomain (Haraka/2.8.18) with ESMTPA id 349C9C2B-491A-4925-A687-3EF14038C344.1 envelope-from <huxin@xxx.com> (authenticated bits=0); Tue, 03 Jul 2018 14:18:13 +0200',
     {
       from_hostname = 'aaa.cn',
       from_ip = '1.1.1.1',
       real_ip = '1.1.1.1',
     }
    },
    {'from [192.83.172.101] by (HELLO 148.251.238.35 ) (148.251.238.35) by guovswzqkvry051@sohu.com with gg login by AOL 6.0 for Windows US sub 008 SMTP  ; Tue, 03 Jul 2018 09:01:47 -0300',
     {
       from_ip = '192.83.172.101',
       by_hostname = '',
     }
    },
  }

  local task = ffi.C.rspamd_task_new(nil, nil)
  local NULL = ffi.new 'void*'
  local function ffi_string(fs)
    if fs ~= NULL then return ffi.string(fs) end
    return nil
  end

  for i,c in ipairs(cases) do
    test("Parse received " .. i, function()
      local hdr = ffi.new("struct received_header")
      c[1] = c[1]:gsub('\n', ' ') -- Replace folding
      ffi.C.rspamd_smtp_received_parse(task, c[1], #c[1], hdr)

      for k,v in pairs(c[2]) do
        if k == 'from_hostname' then
          if #v > 0 then
            assert_equal(v, ffi_string(hdr.from_hostname),
                string.format('%s: from_hostname: %s, expected: %s',
                    c[1], ffi_string(hdr.from_hostname), v))
          else
            assert_nil(hdr.from_hostname,
                string.format('%s: from_hostname: %s, expected: nil',
                c[1], ffi_string(hdr.from_hostname)))
          end
        elseif k == 'from_ip' then
          if #v > 0 then
            assert_equal(v, ffi_string(hdr.from_ip),
                string.format('%s: from_ip: %s, expected: %s',
                    c[1], ffi_string(hdr.from_ip), v))
          else
            assert_nil(hdr.from_ip,
                string.format('%s: from_ip: %s, expected: nil',
                c[1], ffi_string(hdr.from_ip)))
          end
        elseif k == 'real_ip' then
          if #v > 0 then
            assert_equal(v, ffi_string(hdr.real_ip),
                string.format('%s: real_ip: %s, expected: %s',
                    c[1], ffi_string(hdr.real_ip), v))
          else
            assert_nil(hdr.real_ip,
                string.format('%s: real_ip: %s, expected: nil',
                c[1], ffi_string(hdr.real_ip)))
          end
        elseif k == 'by_hostname' then
          if #v > 0 then
            assert_equal(v, ffi_string(hdr.by_hostname),
                string.format('%s: by_hostname: %s, expected: %s',
                    c[1], ffi_string(hdr.by_hostname), v))
          else
            assert_nil(hdr.by_hostname,
                string.format('%s: by_hostname: %s, expected: nil',
                    c[1], ffi_string(hdr.by_hostname)))
          end
        end
      end
    end)

  end
end)