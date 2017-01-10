---
layout: doc_modules
title: Neural network module
---
# Neural network module

Neural network module is an experimental module that allows to perform post-classification of messages based on their current symbols and some training corpus obtained from the previous learns.

To use this module, you need to build Rspamd with `libfann` support. It is normally enabled if you use pre-built packages, however, it could be specified using `-DENABLE_FANN=ON` to `cmake` command during build process.

The idea behind this module is to learn which symbol combinations are common for spam and which are common for ham. To achieve this goal, fann module studies log files via `log_helper` worker unless gathering some reasonable amount of log samples (`1k` by default). Neural network is learned for spam when a message has `reject` action (definite spam) and it is learned as ham when a message has negative score. You could also use your own criteria for learning.

Training is performed in background and after some amount of trains (`1k` again) neural network is updated on the disk allowing scanners to load and update their own data.

After some amount of such iterations (`10` by default), the training process removes old neural network and starts training a new one. This is done to ensure that old data does not influence the current processing. The neural network is also reset when you add or remove rules from Rspamd. Once trained, neural network data is saved into Redis where all Rspamd scanners share their learning data. Redis is also used to store intermediate train vectors. ANN and training data is saved in Redis compressed using `zstd` compressor.

## Configuration

First of all, you need a special worker called `log_helper` to accept rspamd scan results. This logger has a trivial setup:

`/etc/rspamd/rspamd.conf.local`:

~~~ucl
worker "log_helper" {
  count = 1;
}
~~~

Make sure at least one Redis server is [specified]({{ site.baseurl }}/doc/configuration/redis.html) in common `redis` section. Alternatively, you can define Redis server in the module configuration:

`local.d/fann_redis.conf`:

~~~ucl
fann_redis {
  servers = "localhost";
}
~~~

## Settings usage

TODO
