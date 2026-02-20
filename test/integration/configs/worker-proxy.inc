#Proxy worker configuration

bind_socket = "*:50004";
count = 1;
timeout = 120s;
upstream "local" {
	default = yes;
	self_scan = no;
  hosts = "localhost:50001";
  encryption_key = "{= env.WORKER_PUBKEY =}";
}

milter = no;

#Enable encryption for proxy connections
keypair {
	pubkey = "{= env.PROXY_PUBKEY =}";
	privkey = "{= env.PROXY_PRIVKEY =}";
}
