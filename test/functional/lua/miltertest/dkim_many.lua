print('Check we get multiple dkim signatures')

dofile './lib.lua'
dofile './data_dkim.lua'

setup()

send_message(innocuous_msg, multi_hdrs, 'test-id', 'foo@cacophony.za.org', {'nerf@example.org'})
check_headers(2)

teardown()
