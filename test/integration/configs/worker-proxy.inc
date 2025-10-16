#Proxy worker configuration

bind_socket = "*:50004";
count = 1;
timeout = 120s;
upstream "local"
{
	default = yes;
	self_scan = yes;
}

#Enable milter protocol
milter = yes;

#Enable encryption for proxy connections
keypair
{
	pubkey = "{= env.PROXY_PUBKEY =}";
	privkey = "{= env.PROXY_PRIVKEY =}";
}
