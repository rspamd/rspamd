print('Check we will reject a message')

require './lib'
require './data'

setup()

send_message(gtube)
check_gtube()

teardown()
