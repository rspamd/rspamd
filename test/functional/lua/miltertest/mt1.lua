print('Check we will accept a message')

dofile './lib.lua'
dofile './data.lua'

setup()

send_message(innocuous_msg, innocuous_hdrs, 'test-id', 'nerf@example.org', {'nerf@example.org'})
check_accept()

teardown()
