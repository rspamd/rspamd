#  Copyright 2024 Vsevolod Stakhov
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import shutil
import socket

CONTROLLER_ERRORS = True
HAVE_MILTERTEST = shutil.which('miltertest') and True or False
RSPAMD_EXTERNAL_RELAY_ENABLED = False
RSPAMD_KEY_PVT1 = 'ekd3x36tfa5gd76t6pa8hqif3ott7n1siuux68exbkk7ukscte9y'
RSPAMD_KEY_PUB1 = 'm8kneubpcjsb8sbsoj7jy7azj9fdd3xmj63txni86a8ye9ncomny'
RSPAMD_KEY_PUB2 = 'mbggdnw3tdx7r3ruakjecpf5hcqr4cb4nmdp1fxynx3drbyujb3y'
RSPAMD_KEY_PUB3 = 'zhypei8sartqrtow84dddgp5exh3gsr65kbw88wj7ppot1bwmuiy'
RSPAMD_LOCAL_ADDR = '127.0.0.1'
RSPAMD_MAP_WATCH_INTERVAL = '1min'
RSPAMD_PORT_CONTROLLER = 56790
RSPAMD_PORT_CONTROLLER_SLAVE = 56793
RSPAMD_PORT_FUZZY = 56791
RSPAMD_PORT_FUZZY_SLAVE = 56792
RSPAMD_PORT_NORMAL = 56789
RSPAMD_PORT_NORMAL_SLAVE = 56794
RSPAMD_PORT_PROXY = 56795
RSPAMD_PORT_CLAM = 2100
RSPAMD_PORT_FPROT = 2101
RSPAMD_PORT_FPROT2_DUPLICATE = 2102
RSPAMD_PORT_AVAST = 2103
RSPAMD_P0F_SOCKET = '/tmp/p0f.sock'
RSPAMD_REDIS_ADDR = '127.0.0.1'
RSPAMD_REDIS_PORT = 56379
RSPAMD_NGINX_ADDR = '127.0.0.1'
RSPAMD_NGINX_PORT = 56380
RSPAMD_GROUP = 'nogroup'
RSPAMD_USER = 'nobody'
SOCK_DGRAM = socket.SOCK_DGRAM
SOCK_STREAM = socket.SOCK_STREAM
