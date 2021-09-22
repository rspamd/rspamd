-- inet addr tests

context("Received headers parser", function()
  local ffi = require("ffi")
  local rspamd_ip = require "rspamd_ip"

  ffi.cdef[[
    struct received_header {
      const char *from_hostname;
      const char *from_ip;
      const char *real_hostname;
      const char *real_ip;
      const char *by_hostname;
      const char *for_mbox;
      void *for_addr;
      void *addr;
      void *hdr;
      long timestamp;
      int flags; /* See enum rspamd_received_type */
      struct received_header *prev, *next;
  };
  struct rspamd_task * rspamd_task_new(struct rspamd_worker *worker, struct rspamd_config *cfg);
  int rspamd_smtp_received_parse (struct rspamd_task *task,
    const char *data, size_t len, struct received_header *rh);
  ]]

  local cases = {
    {[[from smtp11.mailtrack.pl (smtp11.mailtrack.pl [185.243.30.90])]],
     {
       real_ip = '185.243.30.90',
       real_hostname = 'smtp11.mailtrack.pl'
     },
    },
    {[[from asx121.turbo-inline.com [7.165.23.113] by mx.reskind.net with QMQP; Fri, 08 Feb 2019 06:56:18 -0500]],
     {
       real_ip = '7.165.23.113',
       real_hostname = 'asx121.turbo-inline.com',
     }
    },
    {[[from server.chat-met-vreemden.nl (unknown [IPv6:2a01:7c8:aab6:26d:5054:ff:fed1:1da2])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by mx1.freebsd.org (Postfix) with ESMTPS id CF0171862
	for <test@example.com>; Mon,  6 Jul 2015 09:01:20 +0000 (UTC)
	(envelope-from upwest201diana@outlook.com)]],
      {
        real_ip = '2a01:7c8:aab6:26d:5054:ff:fed1:1da2',
        from_hostname = 'server.chat-met-vreemden.nl',
        real_hostname = '',
        by_hostname = 'mx1.freebsd.org',
      },
    },
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
       from_ip = '2a02:898:31::48:4558:736d:7470',
       real_ip = '2a02:898:31::48:4558:736d:7470',
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
    {'from [192.83.172.101] (HELLO 148.251.238.35) (148.251.238.35) by guovswzqkvry051@sohu.com with gg login by AOL 6.0 for Windows US sub 008 SMTP  ; Tue, 03 Jul 2018 09:01:47 -0300',
     {
       from_ip = '192.83.172.101',
       by_hostname = '',
     },
    },
    {'from [61.174.163.26] (helo=host) by sc8-sf-list1.sourceforge.net with smtp (Exim 3.31-VA-mm2 #1 (Debian)) id 18t2z0-0001NX-00 for <razor-users@lists.sourceforge.net>; Wed, 12 Mar 2003 01:57:10 -0800',
     {
       from_ip = '61.174.163.26',
       by_hostname = 'sc8-sf-list1.sourceforge.net',
     },
    },
    {[[from [127.0.0.1] (unknown [65.19.167.131])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by mail01.someotherdomain.org (Postfix) with ESMTPSA id 43tYMW2yKHz50MHS
	for <user2@somedomain.com>; Mon,  4 Feb 2019 16:39:35 +0000 (GMT)]],
     {
       from_ip = '65.19.167.131',
       real_ip = '65.19.167.131',
       by_hostname = 'mail01.someotherdomain.org',
       ['for'] = 'user2@somedomain.com',
     }
    },
    {[[from example.com ([]) by example.com with ESMTP id 2019091111 ; Thu, 26 Sep 2019 11:19:07 +0200]],
      {
        by_hostname = 'example.com',
      },
    },
    {[[from 171-29.br (1-1-1-1.z.com.br [1.1.1.1]) by x.com.br (Postfix) with;ESMTP id 44QShF6xj4z1X for <hey@y.br>; Thu, 21 Mar 2019 23:45:46 -0300 : <g @yi.br>]],
       {
         from_hostname = '171-29.br',
         real_ip = '1.1.1.1',
         by_hostname = 'x.com.br',
       }
    },
    {[[from [127.0.0.1] ([127.0.0.2])
        by smtp.gmail.com with ESMTPSA id xxxololo]],
     {
       from_hostname = '127.0.0.1',
       real_ip = '127.0.0.2',
       by_hostname = 'smtp.gmail.com'
     }
    },
  }

  local task = ffi.C.rspamd_task_new(nil, nil)
  local NULL = ffi.new 'void*'
  local function ffi_string(fs)
    if fs ~= NULL then return ffi.string(fs) end
    return nil
  end
  local function ip_check(ret)
    local sret = ffi_string(ret)

    if not sret then return 'null' end
    local ip = rspamd_ip.from_string(sret)

    if not ip then return 'not ip' end
    if not ip:is_valid() then return 'unparsed' end
    return tostring(ip)
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
            local got_string = ip_check(hdr.from_ip)
            local expected_string = tostring(rspamd_ip.from_string(v))
            assert_equal(expected_string, got_string,
                string.format('%s: from_ip: %s, expected: %s',
                    expected_string, got_string, v))
          else
            assert_nil(hdr.from_ip,
                string.format('%s: from_ip: %s, expected: nil',
                c[1], ffi_string(hdr.from_ip)))
          end
        elseif k == 'real_ip' then
          if #v > 0 then
            local got_string = ip_check(hdr.real_ip)
            local expected_string = tostring(rspamd_ip.from_string(v))
            assert_equal(expected_string, got_string,
                string.format('%s: real_ip: %s, expected: %s',
                    expected_string, got_string, v))
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
        elseif k == 'for' then
          if #v > 0 then
            assert_equal(v, ffi_string(hdr['for_mbox']),
                string.format('%s: for: %s, expected: %s',
                    c[1], ffi_string(hdr['for_mbox']), v))
          else
            assert_nil(hdr['for_mbox'],
                string.format('%s: for: %s, expected: nil',
                    c[1], ffi_string(hdr['for_mbox'])))
          end
        end
      end
    end)

  end
end)