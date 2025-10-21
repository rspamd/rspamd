#Fuzzy storage worker configuration

bind_socket = "*:50003";
use_tcp = true;
count = 1;
backend = "redis";
hashfile = "/var/lib/rspamd/fuzzy.db";
expire = 90d;
allow_update = ["0.0.0.0/0", "::/0"];
encrypted_only = true;

keypair {
	privkey = "{= env.FUZZY_WORKER_PRIVKEY =}";
	pubkey = "{= env.FUZZY_WORKER_PUBKEY =}";
}
