--[[
Copyright (c) 2015, Vsevolod Stakhov <vsevolod@highsecure.ru>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
]]--

context("Headers folding unit test", function()
  local util = require("rspamd_util")

  test("Headers folding", function()
    -- {header, value}, "expected result"
    local cases = {
      {{"test", "test"}, "test"},
      {{"test1", "_abc _def _ghi _fdjhfd _fhdjkfh _dkhkjd _fdjkf _dshfdks _fhdjfdkhfk _dshfds _fdsjk _fdkhfdks _fdsjf _dkf"},
        "_abc _def _ghi _fdjhfd _fhdjkfh _dkhkjd _fdjkf _dshfdks _fhdjfdkhfk\r\n\t_dshfds _fdsjk _fdkhfdks _fdsjf _dkf"
      },
      {{"Test1", "_abc _def _ghi _fdjhfd _fhdjkfh _dkhaaaaaaaaaaakjdfdjkfdshfdksfhdjfdkhfkdshfdsfdsjkfdkhfdksfdsjf _dkf"},
        "_abc _def _ghi _fdjhfd _fhdjkfh\r\n\t_dkhaaaaaaaaaaakjdfdjkfdshfdksfhdjfdkhfkdshfdsfdsjkfdkhfdksfdsjf _dkf"
      },
      {{"Content-Type", "multipart/mixed;\r\n\tboundary=\"---- =_NextPart_000_01BDBF1F.DA8F77EE\"hhhhhhhhhhhhhhhhhhhhhhhhh fjsdhfkjsd fhdjsfhkj"},
        "multipart/mixed;\r\n\tboundary=\"---- =_NextPart_000_01BDBF1F.DA8F77EE\"hhhhhhhhhhhhhhhhhhhhhhhhh\r\n\tfjsdhfkjsd fhdjsfhkj"
      },
      {{"Content-Type", "multipart/mixed;\r\n\tboundary=\"---- =_NextPart_000_01BDBF1F.DA8F77EE\"hkjhgkfhgfhgf\"hfkjdhf fhjf fghjghf fdshjfhdsj\" hgjhgfjk"},
        "multipart/mixed;\r\n\tboundary=\"---- =_NextPart_000_01BDBF1F.DA8F77EE\"hkjhgkfhgfhgf\"hfkjdhf fhjf fghjghf fdshjfhdsj\" hgjhgfjk"
      },
      {{"Content-Type", "Content-Type: multipart/mixed;\r\n\tboundary=\"---- =_NextPart_000_01BDBF1F.DA8F77EE\" abc def ghfdgfdsgj fdshfgfsdgfdsg hfsdgjfsdg fgsfgjsg"},
        "Content-Type: multipart/mixed;\r\n\tboundary=\"---- =_NextPart_000_01BDBF1F.DA8F77EE\" abc def ghfdgfdsgj\r\n\tfdshfgfsdgfdsg hfsdgjfsdg fgsfgjsg"
      },
      {{"X-Spam-Symbols", "Returnpath_BL2,HFILTER_FROM_BOUNCE,R_PARTS_DIFFER,R_IP_PBL,R_ONE_RCPT,R_googleredir,R_TO_SEEMS_AUTO,R_SPF_NEUTRAL,R_PRIORITY_3,RBL_SPAMHAUS_PBL,HFILTER_MID_NOT_FQDN,MISSING_CTE,R_HAS_URL,RBL_SPAMHAUS_CSS,RBL_SPAMHAUS_XBL,BAYES_SPAM,RECEIVED_RBL10"},
      "Returnpath_BL2,HFILTER_FROM_BOUNCE,R_PARTS_DIFFER,\r\n\tR_IP_PBL,R_ONE_RCPT,R_googleredir,R_TO_SEEMS_AUTO,R_SPF_NEUTRAL,R_PRIORITY_3,\r\n\tRBL_SPAMHAUS_PBL,HFILTER_MID_NOT_FQDN,MISSING_CTE,R_HAS_URL,RBL_SPAMHAUS_CSS,\r\n\tRBL_SPAMHAUS_XBL,BAYES_SPAM,RECEIVED_RBL10"
      },
    }

    for _,c in ipairs(cases) do
      local fv = util.fold_header(c[1][1], c[1][2])
      assert_not_nil(fv)
      assert_equal(fv, c[2], string.format("'%s' doesn't match with '%s'",
        c[2], fv))
    end

  end)
end)
