# Rspamd statistic settings

## Introduction

Statistics is used by rspamd to define the `class` of message: either spam or ham. The overall algorithm is based on Bayesian theorem
that defines probabilities combination. In general, it defines the probability of that a message belongs to the specified class (namely, `spam` or `ham`)
base on the following factors:

- the probability of a specific token to be spam or ham (which means efficiently count of a token's occurences in spam and ham messages)
- the probability of a specific token to appear in a message (which efficiently means frequency of a token divided by a number of tokens in a message)

However, rspamd uses more advanced techniques to combine probabilities, such as sparsed bigramms (OSB) and inverse chi-square distribution.
The key idea of `OSB` algorithm is to use not merely single words as tokens but combinations of words weighted by theirs positions.
This schema is displayed in the following picture:

![OSB algorithm](https://rspamd.com/img/rspamd-schemes.004.png "Rspamd OSB scheme")

The main disadvantage is the amount of tokens which is multiplied by size of window. In rspamd, we use a window of 5 tokens that means that 
the number of tokens is about 5 times larger than the amount of words.

Statistical tokens are stored in statfiles which, in turn, are mapped to specific backends. This architecture is displayed in the following image:

![Statistics architecture](https://rspamd.com/img/rspamd-schemes.005.png "Rspamd statistics architecture")

Starting from rspamd 1.0, we propose to use `sqlite3` as backed and `osb` as tokenizer. That also enables additional features, such as tokens normalization and
metainformation in statistics. The following configuration demonstrates the recommended statistics configuration:

~~~nginx
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
first recipient for user-based statistics which might be inappropriate for your configuration (however, rspamd merely uses SMTP recipients, not MIME ones and prefer
the special LDA header called `Deliver-To` that can be appended by `-d` options for `rspamc`). To enable per-user statistics, just add `users_enabled = true` property
to the **classifier** configuration. You can use per-user and per-language statistics simulataneously. For both types of spearation, rspamd also
looks to the default language and default user's statistics allowing to have the common set of tokens shared for all users/languages.