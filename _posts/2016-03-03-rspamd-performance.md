---
layout: post
title:  "Rspamd vs Spamassassin performance comparison"
categories: misc
---

Just before `1.2` release, I have measured performance of rspamd comparing to SA. In this experiment, I've taken rspamd master branch with default rules.
Then I've added all rules from SA using [spamassassin]({{ site.url }}{{ site.baseurl }}/doc/modules/spamassassin.html) plugin. Hence, two scanners run with almost exact set of rules.

This set is quite large and it includes about 3k of custom regexp rules. Rspamd runs **without** hyperscan and pcre2, so it performs literally the same job as SA does.
And here are results for about 100k messages being scanned:

	Total False Positives: 517
	Total False Negatives: 348
	Total messages: 101349

	Total SA time: 423942 seconds, total rspamd time: 33149 seconds
	Average SA time: 4182ms/msg, average rspamd time: 327ms/msg seconds

So the difference in checks is **less than 1%** and in many cases rspamd does better job than SA because, for example, multiple hits of URIBL rules, phishing detection and some other
differences. And it's still **13 times** faster than SA. Moreover, it eats less memory and can process more messages in parallel. In other experiments, rspamd was able to process
about 450 messages per second on a single SandyBridge 4 cores scanner box.

I plan to release rspamd 1.2 very soon with a lot of cool features, including dynamic rules updates. I would appreciate any help in testing of the [experimental packages]({{ site.url }}{{ site.baseurl }}/downloads.html). In fact,
they are already used in production and are even more stable than 1.1 branch.
