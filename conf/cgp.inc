# Please don't modify this file as your changes might be overwritten with
# the next update.
#
# This file defines some specific settings that are applicable merely when using
# CommuniGate Pro MTA and it's specific integration

arc {
    sign_networks = [127.2.4.7];
}

dkim_signing {
    sign_networks = [127.2.4.7];
}

options {
    local_addrs = [127.2.4.7];
}
