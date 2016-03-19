# Rspamd statistic settings

## Introduction

Statistics is used by rspamd to define the `class` of message: either spam or ham. The overall algorithm is based on Bayesian theorem
that defines probabilities combination. In general, it defines the probability of that a message belongs to the specified class (namely, `spam` or `ham`)
base on the following factors:

- the probability of a specific token to be spam or ham (which means efficiently count of a token's occurences in spam and ham messages)
- the probability of a specific token to appear in a message (which efficiently means frequency of a token divided by a number of tokens in a message)

## Statistics Architecture

However, rspamd uses more advanced techniques to combine probabilities, such as sparsed bigramms (OSB) and inverse chi-square distribution.
The key idea of `OSB` algorithm is to use not merely single words as tokens but combinations of words weighted by theirs positions.
This schema is displayed in the following picture:

![OSB algorithm](https://rspamd.com/img/rspamd-schemes.004.png "Rspamd OSB scheme")

The main disadvantage is the amount of tokens which is multiplied by size of window. In rspamd, we use a window of 5 tokens that means that 
the number of tokens is about 5 times larger than the amount of words.

Statistical tokens are stored in statfiles which, in turn, are mapped to specific backends. This architecture is displayed in the following image:

![Statistics architecture](https://rspamd.com/img/rspamd-schemes.005.png "Rspamd statistics architecture")

## Statistics Configuration

Starting from rspamd 1.0, we propose to use `sqlite3` as backed and `osb` as tokenizer. That also enables additional features, such as tokens normalization and
metainformation in statistics. The following configuration demonstrates the recommended statistics configuration:

~~~ucl
classifier {
    type = "bayes";
    tokenizer {
        name = "osb";
    }
    cache {
        path = "${DBDIR}/learn_cache.sqlite";
    }
    min_tokens = 11;
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

It is also possible to organize per-user statistics using sqlite3 backend. However, you should ensure that rspamd is called at the
finally delivery stage (e.g. LDA mode) to avoid multi-recipients messages. In case of a multi-recipient message, rspamd would just use the
first recipient for user-based statistics which might be inappropriate for your configuration (however, rspamd preferes SMTP recipients over MIME ones and prioritize
the special LDA header called `Deliver-To` that can be appended by `-d` options for `rspamc`). To enable per-user statistics, just add `users_enabled = true` property
to the **classifier** configuration. You can use per-user and per-language statistics simulataneously. For both types of spearation, rspamd also
looks to the default language and default user's statistics allowing to have the common set of tokens shared for all users/languages.

## Using lua scripts for `per_user` classifier

It is also possible to create custom lua scripts to use customized user or language for a specific task. Here is an example
of such a script for extracting domain names from recipients organizing thus per-domain statistics:

~~~ucl
    classifier {
        tokenizer {
            name = "osb";
        }
        name = "bayes2";
        min_tokens = 11;
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

From version 1.1, rspamd uses independent statistics for users and joint statistics for languages. That means the following:

* If `per_user` is enabled then rspamd looks for users statistics **only**
* If `per_language` is enabled then rspamd looks for language specific statistics **plus** language independent statistics

It is different from 1.0 version where the second approach was used for both cases.

## Using multiple classifiers

Rspamd allows to learn and to check multiple classifiers for a single messages. This might be useful, for example, if you have common and per user statistics. It is even possible to use the same statfiles for these purposes. Classifiers **might** have the same symbols (thought it is not recommended) and they should have a **unique** `name` attribute that is used for learning. Here is an example of such a configuration:

~~~ucl
    classifier {
        tokenizer {
            name = "osb";
        }
        name = "bayes_user";
        min_tokens = 11;
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

    classifier {
        tokenizer {
            name = "osb";
        }
        name = "bayes";
        min_tokens = 11;
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

From version 1.1, it is also possible to specify redis as a backend for statistics and cache of learned messages. Redis is recommended for clustered configurations as it allows simultaneous learn and checks and, besides, is very fast. To setup redis, you could use `redis` backend for a classifier (cache is set to the same servers accordingly).

~~~ucl
    classifier {
        tokenizer {
            name = "osb";
        }
        name = "bayes";
        min_tokens = 11;
        backend = "redis";
        servers = "localhost:6379";
        #write_servers = "localhost:6379"; # If needed another servers for learning
        #password = "xxx"; # Optional password
        #database = "2"; # Optional database id

        statfile {
            symbol = "BAYES_SPAM";
        }
        statfile {
            symbol = "BAYES_HAM";
        }
        per_user = true;
    }
~~~

`per_languages` is not supported by redis - it just stores everything in the same place. `write_servers` are used in the
`master-slave` rotation by default and used for learning, whilst `servers` are selected randomly each time:

	write_servers = "master.example.com:6379:10, slave.example.com:6379:1"
	write_servers = "master.example.com:6379, slave.example.com:6379"

Where the last number is priority used to distinguish master from slave.

## Autolearning

From version 1.1, rspamd supports autolearning for statfiles. Autolearning is applied after all rules are processed (including statistics) if and only if the same symbol has not been inserted. E.g. a message won't be learned as spam if `BAYES_SPAM` is already in the results of checking.

There are 3 possibilities to specify autolearning:

* `autolearn = true`: autolearning is performing as spam if a message has `reject` action and as ham if a message has **negative** score
* `autolearn = [1, 10]`: autolearn as ham if score is less than minimum of 2 numbers (< `1` here) and as spam if score is more than maximum of 2 numbers (> `10` in this case)
* `autolearn = "return function(task) ... end"`: use the following lua function to detect if autolearn is needed (function should return 'ham' if learn as ham is needed and string 'spam' if learn as spam is needed, if no learn is needed then a function can return anything including `nil`)

Redis backend is highly recommended for autolearning purposes since it's the only backend with high concurrency level when multiple writers are properly synchronized.
