# CORPUS TESTING

Run corpus_test.lua to test emails and generate log. These logs can be used for generating statistics/rescoring.

Example:

`lua corpus_test.lua -a path/to/ham/dir -s path/to/spam/dir -o results.log`

Use -h option to get more info about usage.

Log file consists of one line per email. It contains actual email_type, score, action, symbols in that order.

# STATISTICS

Use statistics.lua to infer useful information from the log file generated in previous step. For generating statistics specify spam threshold score using -t. Feed in log file using input redirection.

### Example:

`rspamadm lua statistics.lua -a path/to/log/file -a -t -a 15`

Use `rspamadm lua statistics.lua -a -h` to get more info about usage

Statistics contains two different information - File stats and symbol stats.

### File stats:

**Number of emails**: Number of emails read from log  
**Number of spam**: Number of spam emails read from log  
**Number of ham**: Number of ham emails read from log  
**Spam percentage**: Percentage of spam emails read from log  
**Ham percentage**: Percentage of ham emails read from log  
**False positive rate**: Percentage of ham emails that were falsely classified as spam  
**False negative rate**: Percentage of spam emails that were falsely classified as ham  
**Overall Accuracy**: Overall accuracy of classification

### Symbol stats:

Each line presents statistics about a symbol read from the log.  

**Overall**: % of emails hit by a symbol  
**Spam**: % of spam emails hit by a symbol  
**Ham**: % of ham emails hit by a symbol  
**S/O**: % spam emails hit over all its hits  
	   (i.e What is the probability that it hits a spam message when it is fired)  


# Rescoring

Use rescore.lua on logs generated from corpus-test to find optimal symbol scores using perceptron.

### Example:
	
	rspamadm lua -a -l -a path/to/log/dir -a -i -a 1000 -a -r -a 1 -a --diff -a -o -a new.scores
  
  
  
  
