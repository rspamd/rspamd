---
layout: post
title:  "Rspamd bayes engine benchmark"
categories: misc
---

I have recently decided to compare [Bayes classifier](https://en.wikipedia.org/wiki/Bayes_classifier) in Rspamd with the closest analogues. I have tried 3 competitors:

1. Rspamd (version 1.4 git master)
2. Bogofilter - classical bayesian filter
3. Dspam - the most advanced bayesian filter used by many projects and people

For Dspam, I have tested both `chain` and `osb` tokenization modes. I have tried to test `chi-square` probabilities combiner (since the same algorithm is used in Rspamd), however, I could not make it working somehow.

## Testing methodology

First of all, I have collected some corpus of messages with about 1k of spam messages and 1k of ham messages. All messages were carefully selected and manually checked. Then, I have written a small [script](https://github.com/vstakhov/rspamd/blob/master/utils/classifier_test.pl) that performs the following steps:

1. Split corpus randomly into two equal parts with about 500 messages of Ham and Spam correspondingly
2. Learn bayes classifier using the desired spam filtering engine (`-d` for Dspam, `-b` for Bogofilter)
3. Use the rest of messages to test classifier after learning procedure

This script collects 6 main values for each classifier:

1. Spam/Ham detection rate - number of messages that are **correctly** recognized as spam and ham
2. Spam FP rate - number of false positives for Spam: **HAM** messages that are recognized as **SPAM**
3. Ham FP rate - number of false positives for Ham: **SPAM** messages that are recognized as **HAM**
4. Ham and Spam FN rate - number of messages that are not recognized as Ham or Spam (but not classified as the opposite class, meaning uncertainity for a classifier)

The worse error for a classifier is Spam False Positive, since it detects an innocent message as Spam. Ham FP and false negatives are more permissive: they just mean that you receive more spam than you want.

## Results

The raw results are pasted at the following [gist](https://gist.github.com/vstakhov/a8e2cf931d87a88622b8d33245fce83c).

Here are the corresponding graphs for detection rate and errors for the competitors.

<center><img class="img-responsive" src="/img/bayes_rate.png" width="75%"></center>

<center><img class="img-responsive" src="/img/bayes_error.png" width="75%"></center>

## Conclusions

Rspamd Bayes performs very well comparing to the competitors. It provides higher spam detection rate comparing to both Dspam and Bogofilter. All competitors demonstrated the common spam false positives rate. However, Dspam is more aggressive in marking messages as Ham (which is not bad because Bayes is the only check Dspam provides). Rspamd is also much faster in learning and testing. With Redis backend it learns 1k messages in less than 5 seconds. Dspam and Bogofilter require about 30 seconds to learn. The overall quality of Bayes classifier is high enough to recommend using it in the production environments or to replace Dspam and Bogofilter for your email service.