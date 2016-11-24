---
layout: doc_conf
title: Rspamd Statistics
---
# Rspamd statistic settings

## Introduction

Statistics is used by Rspamd to define the `class` of message: either spam or ham. The overall algorithm is based on Bayesian theorem
that defines probabilities combination. In general, it defines the probability of that a message belongs to the specified class (namely, `spam` or `ham`)
base on the following factors:

- the probability of a specific token to be spam or ham (which means efficiently count of a token's occurrences in spam and ham messages)
- the probability of a specific token to appear in a message (which efficiently means frequency of a token divided by a number of tokens in a message)

## Statistics Architecture

However, Rspamd uses more advanced techniques to combine probabilities, such as sparsed bigramms (OSB) and inverse chi-square distribution.
The key idea of `OSB` algorithm is to use not merely single words as tokens but combinations of words weighted by theirs positions.
This schema is displayed in the following picture:

<img class="img-responsive" width="50%" src="{{ site.baseurl }}/img/rspamd-schemes.004.png">

The main disadvantage is the amount of tokens which is multiplied by size of window. In Rspamd, we use a window of 5 tokens that means that
the number of tokens is about 5 times larger than the amount of words.

Statistical tokens are stored in statfiles which, in turn, are mapped to specific backends. This architecture is displayed in the following image:

<img class="img-responsive" width="50%" src="{{ site.baseurl }}/img/rspamd-schemes.005.png">

## Statistics Configuration

Starting from Rspamd 1.0, we propose to use `sqlite3` as backed and `osb` as tokenizer. That also enables additional features, such as tokens normalization and
metainformation in statistics. The following configuration demonstrates the recommended statistics configuration:

~~~ucl
# Classifier's algorithm is BAYES
classifier "bayes" {
    tokenizer {
        name = "osb";
    }

    # Unique name used to learn the specific classifier
    name = "common_bayes";

    cache {
        path = "${DBDIR}/learn_cache.sqlite";
    }

    # Minimum number of words required for statistics processing
    min_tokens = 11;
    # Minimum learn count for both spam and ham classes to perform classification
    min_learns = 200;

    backend = "sqlite3";
    languages_enabled = true;
    statfile {
        symbol = "BAYES_HAM";
        path = "${DBDIR}/bayes.ham.sqlite";
        spam = false;
    }
    statfile {
        symbol = "BAYES_SPAM";
        path = "${DBDIR}/bayes.spam.sqlite";
        spam = true;
    }
}
~~~

It is also possible to organize per-user statistics using SQLite3 backend. However, you should ensure that Rspamd is called at the
finally delivery stage (e.g. LDA mode) to avoid multi-recipients messages. In case of a multi-recipient message, Rspamd would just use the
first recipient for user-based statistics which might be inappropriate for your configuration (however, Rspamd prefers SMTP recipients over MIME ones and prioritize
the special LDA header called `Deliver-To` that can be appended by `-d` options for `rspamc`). To enable per-user statistics, just add `users_enabled = true` property
to the **classifier** configuration. You can use per-user and per-language statistics simultaneously. For both types of statistics, Rspamd also
looks to the default language and default user's statistics allowing to have the common set of tokens shared for all users/languages.

## Using Lua scripts for `per_user` classifier

It is also possible to create custom Lua scripts to use customized user or language for a specific task. Here is an example
of such a script for extracting domain names from recipients organizing thus per-domain statistics:

~~~ucl
classifier "bayes" {
    tokenizer {
        name = "osb";
    }

    name = "bayes2";

    min_tokens = 11;
    min_learns = 200;

    backend = "sqlite3";
    per_language = true;
    per_user = <<EOD
return function(task)
    local rcpt = task:get_recipients(1)

if rcpt then
    one_rcpt = rcpt[1]
    if one_rcpt['domain'] then
        return one_rcpt['domain']
    end
end

return nil
end
EOD
    statfile {
        path = "/tmp/bayes2.spam.sqlite";
        symbol = "BAYES_SPAM2";
    }
    statfile {
        path = "/tmp/bayes2.ham.sqlite";
        symbol = "BAYES_HAM2";
    }
}
~~~

## Applying per-user and per-language statistics

From version 1.1, Rspamd uses independent statistics for users and joint statistics for languages. That means the following:

* If `per_user` is enabled then Rspamd looks for users statistics **only**
* If `per_language` is enabled then Rspamd looks for language specific statistics **plus** language independent statistics

It is different from 1.0 version where the second approach was used for both cases.

## Using multiple classifiers

Rspamd allows to learn and to check multiple classifiers for a single messages. This might be useful, for example, if you have common and per user statistics. It is even possible to use the same statfiles for these purposes. Classifiers **might** have the same symbols (thought it is not recommended) and they should have a **unique** `name` attribute that is used for learning. Here is an example of such a configuration:

~~~ucl
classifier "bayes" {
    tokenizer {
        name = "osb";
    }

    name = "users";
    min_tokens = 11;
    min_learns = 200;
    backend = "sqlite3";
    per_language = true;
    per_user = true;

    statfile {
        path = "/tmp/bayes.spam.sqlite";
        symbol = "BAYES_SPAM_USER";
    }
    statfile {
        path = "/tmp/bayes.ham.sqlite";
        symbol = "BAYES_HAM_USER";
    }
}

classifier "bayes" {
    tokenizer {
        name = "osb";
    }

    name = "common";
    min_tokens = 11;
    min_learns = 200;
    backend = "sqlite3";
    per_language = true;

    statfile {
        path = "/tmp/bayes.spam.sqlite";
        symbol = "BAYES_SPAM";
    }
    statfile {
        path = "/tmp/bayes.ham.sqlite";
        symbol = "BAYES_HAM";
    }
}
~~~

To learn specific classifier, you can use `-c` option for `rspamc` (or `Classifier` HTTP header):

	rspamc -c bayes learn_spam ...
	rspamc -c bayes_user -d user@example.com learn_ham ...

## Redis statistics

From version 1.1, it is also possible to specify Redis as a backend for statistics and cache of learned messages. Redis is recommended for clustered configurations as it allows simultaneous learn and checks and, besides, is very fast. To setup Redis, you could use redis backend for a classifier (cache is set to the same servers accordingly).

The following configuration is a full featured example of how you can set up redis for the statistics. Please edit `/etc/rspamd/local.d/statistic.conf` and paste the code.

For a redis classifier, you need to set the backend to `redis`. It is important to define the `servers` parameter, as it is not taken from a global configuration (You might have defined redis for LUA modules). If you want to have bayes auto learning, you need to tell it to the configuration file. See below for further explanations on this parameter.

Bayes tokens can be stored per user when you define a LUA function.

The statfile parameters are used for the key names in redis. You should also specify, which symbol is spam and which is for ham.

At the end of this configuration file, you find a learning condition LUA function. It keeps track of already learned tokens.

~~~ucl
classifier "bayes" {
    tokenizer {
    name = "osb";
    }

    backend = "redis";
    servers = "127.0.0.1:6379";
    min_tokens = 11;
    min_learns = 200;
    autolearn = true;

    per_user = <<EOD
return function(task)
    local rcpt = task:get_recipients(1)

if rcpt then
    one_rcpt = rcpt[1]
    if one_rcpt['domain'] then
        return one_rcpt['domain']
    end
end

return nil
end
EOD

    statfile {
        symbol = "BAYES_HAM";
        spam = false;
    }
    statfile {
        symbol = "BAYES_SPAM";
        spam = true;
    }
    learn_condition =<<EOD
return function(task, is_spam, is_unlearn)
    local prob = task:get_mempool():get_variable('bayes_prob', 'double')

    if prob then
        local in_class = false
        local cl
        if is_spam then
            cl = 'spam'
            in_class = prob >= 0.95
        else
            cl = 'ham'
            in_class = prob <= 0.05
        end

        if in_class then
            return false,string.format('already in class %s; probability %.2f%%',
            cl, math.abs((prob - 0.5) * 200.0))
        end
    end

    return true
end
EOD
}
~~~

`per_languages` is not supported by Redis - it just stores everything in the same place. `write_servers` are used in the master-slave rotation by default and used for learning, whilst read-only servers are selected randomly each time:

Supported parameters for the redis backend are:

- `tokenizer`: leave it as shown for now. Currently only osb is supported
- `backend`: set it to redis
- `servers`: IP or hostname with port for the redis server. Use an IP for the loopback interface, if you have defined localhost in /etc/hosts for both IPv4 and IPv6, or your redis server will not be found!
- `write_servers` (optional): If needed, define dedicated servers for learning
- `password` (optional): Password for the redis server
- `database` (optional): Database to use (though it is recommended to use dedicated redis instances and not databases in redis)
- `min_tokens` : minimum number of words required for statistics processing
- `min_learns` (optional): minimum learn count for **both** spam and ham classes to perform  classification
- `autolearn` (optional): see below for details
- `per_user` (optional): enable per users statistics. See above
- `statfile`: Define keys for spam and ham mails.
- `learn_condition` (optional): Lua function for autoleraning as described below.

## Autolearning

From version 1.1, Rspamd supports autolearning for statfiles. Autolearning is applied after all rules are processed (including statistics) if and only if the same symbol has not been inserted. E.g. a message won't be learned as spam if `BAYES_SPAM` is already in the results of checking.

There are 3 possibilities to specify autolearning:

* `autolearn = true`: autolearning is performing as spam if a message has `reject` action and as ham if a message has **negative** score
* `autolearn = [-5, 5]`: autolearn as ham if score is less `-5` and as spam if score is more than `5`
* `autolearn = "return function(task) ... end"`: use the following Lua function to detect if autolearn is needed (function should return 'ham' if learn as ham is needed and string 'spam' if learn as spam is needed, if no learn is needed then a function can return anything including `nil`)

Redis backend is highly recommended for autolearning purposes since it's the only backend with high concurrency level when multiple writers are properly synchronized.
