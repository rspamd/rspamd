#Normal worker(scanner) configuration

bind_socket = "*:50001";
count = 2;
task_timeout = 60s;
max_tasks = 1000;

#Enable encryption for inter-worker communication
keypair {
	pubkey = "{= env.RSPAMD_WORKER_PUBKEY =}";
	privkey = "{= env.RSPAMD_WORKER_PRIVKEY =}";
}
