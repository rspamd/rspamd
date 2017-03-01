---
layout: doc_worker_add
title: Rspamd normal worker
---
# Rspamd normal worker

Rspamd normal worker is intended to scan messages for spam. It has the following configuration options available:

* `mime`: turn to `off` if you want to scan non-mime messages (e.g. forum comments or SMS), default: `on`
* `allow_learn`: turn to `on` if you want to learn messages using this worker (usually you should use [controller](controller.html) worker), default: `off`
* `timeout`: input/output timeout, default: `1min`
* `task_timeout`: maximum time to process a single task, default: `8s`
* `max_tasks`: maximum count of tasks processes simultaneously, default: `0` - no limit
* `keypair`: encryption keypair

## Encryption support

To generate a keypair for the scanner you could use:

    rspamadm keypair -u

After that keypair should appear as following:

~~~ucl
keypair {
    pubkey = "tm8zjw3ougwj1qjpyweugqhuyg4576ctg6p7mbrhma6ytjewp4ry";
    privkey = "ykkrfqbyk34i1ewdmn81ttcco1eaxoqgih38duib1e7b89h9xn3y";
}
~~~

You can use its **public** part thereafter when scanning messages as following:

    rspamc --key tm8zjw3ougwj1qjpyweugqhuyg4576ctg6p7mbrhma6ytjewp4ry <file>
