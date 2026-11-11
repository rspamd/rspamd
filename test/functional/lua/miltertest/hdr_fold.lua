print('Check that a header folded right after the colon survives the milter')

dofile './lib.lua'
dofile './data.lua'

local function fold_hdrs(value)
  local hdrs = {}
  for k, v in pairs(innocuous_hdrs) do
    hdrs[k] = v
  end
  hdrs['X-Fold-Test'] = value
  return hdrs
end

-- Without SMFIP_HDR_LEADSPC the MTA strips one space after the colon, but
-- `X-Fold-Test:\r\n <id>` has none, so rspamd must not invent one (issue #6194)
setup(nil, nil, nil, 0)
send_message(innocuous_msg, fold_hdrs('\r\n <fold@example.org>'),
             'test-id', 'nerf@example.org', {'nerf@example.org'})
check_smtp_reply('554', '5.7.1', 'fold preserved')
teardown()

-- With SMFIP_HDR_LEADSPC miltertest sends the value verbatim, leading space
-- included, so rspamd must not add a second one
if SMFIP_HDR_LEADSPC then
  setup(nil, nil, nil, SMFIP_HDR_LEADSPC)
  send_message(innocuous_msg, fold_hdrs('<leadspc@example.org>'),
               'test-id', 'nerf@example.org', {'nerf@example.org'})
  check_smtp_reply('554', '5.7.1', 'leadspc preserved')
  teardown()
end
