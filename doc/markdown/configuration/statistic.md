# Rspamd statistic settings

## Introduction

~~~nginx
classifier {
    type = "bayes";
    tokenizer = "osb-text";
    metric = "default";
    min_tokens = 10;
    max_tokens = 1000;
    statfile {
        symbol = "BAYES_HAM";
        size = 50Mb;
        path = "$DBDIR/bayes.ham";
    }
    statfile {
        symbol = "BAYES_SPAM";
        size = 50Mb;
        path = "$DBDIR/bayes.spam";
    }
}
~~~