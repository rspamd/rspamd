import sys
import argparse
from collections import namedtuple

file_stat = namedtuple('FileStat',
                        'no_of_emails \
                        no_of_spam \
                        no_of_ham \
                        spam_dict \
                        ham_dict \
                        symbol_set \
                        false_positive_rate \
                        false_negative_rate')

sym_stat = namedtuple('SymbolStat',
                      'name \
                      overall \
                      spam_percent \
                      ham_percent \
                      so')

def get_symbol_stats(file_stat):

    symbol_stats = []
    
    for symbol in file_stat.symbol_set:

        spam_hits = 0
        ham_hits = 0
        spam_hits = 0
        
        if symbol in file_stat.spam_dict:
            spam_hits = file_stat.spam_dict[symbol]
        if symbol in file_stat.ham_dict:
            ham_hits = file_stat.ham_dict[symbol]

        total_hits = spam_hits + ham_hits

        name = symbol
        overall = 0
        spam_percent = 0
        ham_percent = 0
        so = 0

        if file_stat.no_of_emails > 0:
            overall = total_hits * 100/ float(file_stat.no_of_emails)
            
        if total_hits > 0:
            spam_percent = spam_hits * 100 / float(total_hits)

        if total_hits > 0:
            ham_percent = ham_hits * 100 / float(total_hits)
            
        so = spam_percent / float(spam_percent + ham_percent)

        symbol_stats.append(sym_stat(name,
                                     round(overall, 2),
                                     round(spam_percent, 2),
                                     round(ham_percent, 2),
                                     round(so, 2)))

    return symbol_stats        

    
def get_file_stats(logs, spam_threshold):

    no_of_emails = len(logs)
    no_of_spam = 0
    no_of_ham = 0
    spam_dict = {}
    ham_dict = {}
    symbol_set = set()

    no_of_fp = 0
    no_of_fn = 0
    
    for line in logs:
        log = line.split()

        no_of_fp += (1 if float(log[2]) >= spam_threshold else 0)        
        no_of_ham += (1 if log[1] == 'HAM' else 0)
        no_of_fn += (1 if float(log[2]) < spam_threshold else 0)        
        no_of_spam += (1 if log[1] == 'SPAM' else 0)

        for symbol in log[3:]:
            symbol_set.add(symbol)

            if log[1] == 'HAM':

                if symbol not in ham_dict:
                    ham_dict[symbol] = 0

                ham_dict[symbol] += 1

            else:
                
                if symbol not in spam_dict:
                    spam_dict[symbol] = 0

                spam_dict[symbol] += 1

    false_positive_rate = 0
    false_negative_rate = 0
    
    if no_of_ham > 0:
        false_positive_rate = no_of_fp * 100 / float(no_of_ham)

    if no_of_spam > 0:
        false_negative_rate = no_of_fn * 100 / float(no_of_spam)                             
    
    return file_stat(no_of_emails,
                     no_of_spam,
                     no_of_ham,
                     spam_dict,
                     ham_dict,
                     symbol_set,
                     false_positive_rate,
                     false_negative_rate)
            
                             
def write_file_stats(file_stat):

    print "File statistics: "
    print
    print "Number of emails: " + str(file_stat.no_of_emails)
    print "Number of spam: " + str(file_stat.no_of_spam)
    print "Number of ham: " + str(file_stat.no_of_ham)
    print "False positive rate: " + str(file_stat.false_positive_rate)
    print "False negative rate: " + str(file_stat.false_negative_rate)
    print

    
def write_sym_stats(sym_stats):
    
    width = len(max([sym.name for sym in sym_stats], key=len)) + 2

    print "Symbol statistics: "
    print 
    print "{} {} {} {} {}".format('SYMBOL'.ljust(width),
                                  'OVERALL'.ljust(9),
                                  'SPAM %'.ljust(8),
                                  'HAM %'.ljust(7),
                                  'S/O'.ljust(5))

    for sym in sym_stats:
        print "{} {} {} {} {}".format(sym.name.ljust(width),
                                      str(sym.overall).ljust(9),
                                      str(sym.spam_percent).ljust(8),
                                      str(sym.ham_percent).ljust(7),
                                      str(sym.so).ljust(5))

def main():

    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-t',
                            '--threshold',
                            help='spam score threshold',
                            type=int)

    args = arg_parser.parse_args()

    if args.threshold is None:
        arg_parser.error('specify spam score threshold')
        return
    
    logs = sys.stdin.readlines()

    file_stat = get_file_stats(logs, args.threshold)

    sym_stats = get_symbol_stats(file_stat)

    write_file_stats(file_stat)
    write_sym_stats(sym_stats)
    
    
if __name__ == "__main__":
    main()
