print('Check we will reject a message')

dofile './lib.lua'
dofile './data.lua'

setup()

send_message(gtube)
check_gtube()

teardown()
