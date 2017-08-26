# CORPUS TESTING

Run corpus_test.lua to test emails and generate log. These logs can be used for generating statistics/rescoring.

Example:

`rspamadm lua corpus_test.lua -a -a -a path/to/ham/dir -a -s -a path/to/spam/dir -a -o -a results.log`

Use -h option to get more info about usage.

Log file consists of one line per email. It contains actual email_type, score, action, symbols in that order.

# STATISTICS

Use statistics.lua to infer useful information from the log file generated in previous step. Use -t option to specify spam threshold.

### Example:

`rspamadm lua statistics.lua -a path/to/log/file -a -t -a 15`

Use `rspamadm lua statistics.lua -a -h` to get more info about usage

Statistics contains two different information - Corpus statistics and Symbols statistics

### Corpus Statistics

**Number of emails**: Number of emails read from log  
**Number of spam**: Number of spam emails read from log  
**Number of ham**: Number of ham emails read from log  
**Spam percentage**: Percentage of spam emails read from log  
**Ham percentage**: Percentage of ham emails read from log  
**False positive rate**: Percentage of ham emails that were falsely classified as spam  
**False negative rate**: Percentage of spam emails that were falsely classified as ham  
**Overall Accuracy**: Overall accuracy of classification

### Symbol Statistics

Each line presents statistics about a symbol read from the log.  

**Overall**: % of emails hit by a symbol  
**Spam**: % of spam emails hit by a symbol  
**Ham**: % of ham emails hit by a symbol  
**S/O**: % spam emails hit over all its hits  
	   (i.e What is the probability that it hits a spam message when it is fired)  


# Rescoring

Use rescore.lua on logs generated from corpus-test to find optimal symbol scores using perceptron. Use -o option to dump new scores in json format.

### Example:
	
	rspamadm lua -a -l -a path/to/log/dir -a --diff -a -o -a new.scores
  

# Example usage

1. Collect ham and spam messages and store them in /ham and /spam directories respectively.
2. Run `rspamadm lua corpus_test.lua -a -a -a path/to/ham/dir -a -s -a path/to/spam/dir -a -o -a results.log`
3. Make a directory for logs files `mkdir logs`
4. Move log files into logs directory `mv results.log logs/`
5. Run `rspamadm lua -a -l -a logs -a --diff -a -o -a new.scores` 
  
  
  
