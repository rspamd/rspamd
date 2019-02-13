print('Check we get single dkim signature')

dofile './lib.lua'
dofile './data_dkim.lua'

setup()

send_message(innocuous_msg, single_hdr, 'test-id', 'foo@invalid.za.org', {'nerf@example.org'})
check_headers(1)

teardown()
