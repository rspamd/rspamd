context("SMTP date functions", function()
  local rspamd_util = require "rspamd_util"

  local cases = {
    {'Mon, 05 Oct 2020 19:05:57 -0000', 1601924757},
    -- space instead of leading zero
    {'Mon,  5 Oct 2020 19:05:57 -0000', 1601924757},
    -- no padding
    {'Mon, 5 Oct 2020 19:05:57 -0000',  1601924757},
    -- no weekday
    {'5 Oct 2020 19:05:57 -0000', 1601924757},
    -- different TZ offsets
    {'Tue, 22 Sep 2020 00:03:14 -0800', 1600761794},
    {'Fri, 02 Oct 2020 20:00:40 +0100', 1601665240},
    {'Mon, 5 Oct 2020 15:48:32 +0530', 1601893112},
    {'Mon, 05 Oct 2020 10:30:36 +1200', 1601850636},
    -- extra comment
    {'Thu, 18 May 2006 16:08:11 +0400 (MSD)', 1147954091},
    {'Thu, 18 May 2006 16:08:11 +0400',       1147954091},
    -- obs_zone
    {'Sat, 26 Sep 2020 17:36:21 GMT',   1601141781},
    {'Sat, 26 Sep 2020 17:36:21 UT',    1601141781},
    {'Sat, 26 Sep 2020 17:36:21 +0000', 1601141781},
    {'Wed, 30 Sep 2020 20:32:31 EDT',   1601512351},
    {'Wed, 30 Sep 2020 20:32:31 -0400', 1601512351},
    {'Wed, 30 Sep 2020 17:32:31 PDT',   1601512351},
    {'Wed, 30 Sep 2020 17:32:31 -0700', 1601512351},
    -- 2 digit year < 50
    {'Mon, 05 Oct 20 06:35:38 GMT',   1601879738},
    {'Mon, 05 Oct 2020 06:35:38 GMT', 1601879738},
    -- 2 digit year >= 50
    {'26 Aug 76 14:30 EDT',   209932200},
    {'26 Aug 1976 14:30 EDT', 209932200},
    -- Year 2038 problem
    {'Tue, 19 Jan 2038 03:14:09 GMT', 2^31 + 1},
    -- double space before TZ
    {'Sat, 29 Aug 2020 08:25:15  +0700', 1598664315},
    -- XXX timestamp corresponding to Sat Dec 30 00:00:00 GMT 1899 returned on error
    --{'Sat, Dec 30 1899 00:00:00 GMT', -2209161600},
    -- Invalid format
    {'Mon Oct  5 20:29:23 BST 2020', nil},
    -- Wrong date
    {'32 Jan 2020 00:00 GMT', nil},
    -- Wrong time
    {'1 Jan 2020 25:00 GMT', nil}
  }

  for _,case in ipairs(cases) do
    test("Parse date: " .. case[1], function()
      local timestamp = rspamd_util.parse_smtp_date(case[1])
      assert_rspamd_eq({
        expect = case[2],
        actual = timestamp
      })
    end)
  end
end)