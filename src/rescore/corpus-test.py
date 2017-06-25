#!/usr/bin/env python

import argparse
import os
import socket
import requests
import json
from os.path import basename
from requests.exceptions import RequestException
from itertools import chain
from Queue import Queue
from threading import Thread
import sys
import time

from utility import get_all_filenames

test_queue = Queue()    # Each element is a tuple: (file_location, email_type)
                        # email_type is either "SPAM" or "HAM"
progress_queue = Queue()                        
test_results = []


def get_test_url(host, port):

    endpoint = "symbols"

    return "http://{}:{}/{}".format(host, port, endpoint)


def is_symbol_field(value):

    is_symbol = False
    
    if type(value) == type(dict()):
        if "score" in value:
            is_symbol = True

    return is_symbol


def get_symbols_from_response(metrics):
                
    symbols = []
            
    for field in metrics:
        if is_symbol_field(metrics[field]):
            symbols.append(field)

    return symbols


def progress_bar(total_emails, width=50):

    done = 0

    print '[{}]'.format(' ' * width),
    
    while True:
        temp = progress_queue.get()
        done += 1
        complete_width = done * width / total_emails
        
        print '\r[{}{}] ({} / {}) done'.format('#' * complete_width,
                                               ' ' * (width - complete_width),
                                               done,
                                               total_emails),

        if done == total_emails:
            print

        sys.stdout.flush()
        
        progress_queue.task_done()
            
            
def test_email(test_url):

    while True:

        file_location, email_type = test_queue.get()

        with open(file_location, 'r') as f:
            try:
                # TODO pass file /path instead                
                response = requests.post(test_url, data=f)
            except RequestException as err:
                print "Connection error."
                print err
            else:

                try:
                    metrics = json.loads(response.text)["default"]
                except KeyError:
                    print "Error testing email: {}. Skipping.".format(file_location)
                    continue
                
                symbols = get_symbols_from_response(metrics)
                action = metrics['action'].replace(' ', '_')
                
                test_results.append('{} {} {} {} {}'.format(basename(file_location),
                                                         email_type,
                                                         metrics['score'],
                                                         action,
                                                         ' '.join(symbols)))

        progress_queue.put("DONE")
        test_queue.task_done()

        
def test_emails(filenames, email_type):
    
    if email_type not in ['HAM', 'SPAM']:
        raise ValueError("Wrong email_type")
        return

    for filename in filenames:
        test_queue.put((filename, email_type))
    
        
def write_test_results(output_file, test_results):

    with open(output_file, 'w') as out:
        out.write('\r\n'.join(test_results))


def print_test_stats(total_time, avg_time, no_of_emails):

    print "Test stats: "
    print "Total time: {}s".format(total_time)
    print "Avg. time per email: {}s".format(avg_time)
    print "Emails scanned: {}".format(no_of_emails)

    
def run_tests(test_url, ham_location, spam_location, no_of_threads=2):

    start_time = time.time()
    
    ham_file_locations = []
    spam_file_locations = []

    if ham_location:
        if os.path.isdir(ham_location):
            ham_file_locations = get_all_filenames(ham_location)
        else:
            ham_file_locations.append(ham_location)

    if spam_location:
        if os.path.isdir(spam_location):
            spam_file_locations = get_all_filenames(spam_location)
        else:
            spam_file_locations.append(spam_location)

    no_of_emails = len(ham_file_locations) + len(spam_file_locations)
    
    threads = [Thread(target=test_email, args=(test_url, ))
               for _ in range(no_of_threads)]        

    progress_thread = Thread(target=progress_bar, args=(no_of_emails, ))
    progress_thread.setDaemon(True)
    progress_thread.start()

    for thread in threads:
        thread.setDaemon(True)
        thread.start()

    test_emails(ham_file_locations, "HAM")
    test_emails(spam_file_locations, "SPAM")

    test_queue.join()
    progress_queue.join()

    total_time = round(time.time() - start_time, 2)
    avg_time = round(total_time / no_of_emails, 2)

    print_test_stats(total_time=total_time,
                     avg_time=avg_time,
                     no_of_emails=no_of_emails)


def main():

    rspamd_host = "127.0.0.1"
    rspamd_port = 11333
    output_file = "results.log"
    no_of_threads = 10

    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-a", "--ham", help="path to ham directory")
    arg_parser.add_argument("-s", "--spam", help="path to spam directory")
    arg_parser.add_argument("-o", "--output",
                            help="path to test results output [Default: results.log]")
    arg_parser.add_argument("-i", "--ip",
                            help="ip of rspamd service [Default: 127.0.0.1]")
    arg_parser.add_argument("-p", "--port",
                            help="rspamd service port number [Default: 11333]",
                            type=int)
    arg_parser.add_argument("-j", "--threads",
                            help="number of threads to run tests [Default: 10]",
                            type=int)
    
    args = arg_parser.parse_args()

    if not (args.ham or args.spam):
        arg_parser.error("Provide atleast one of spam or ham directory")
        arg_parser.print_help()
        return

    if args.ip:
        rspamd_host = args.ip

    if args.port:
        rspamd_port = args.port

    if args.output:
        output_file = args.output

    if args.threads:
        no_of_threads = args.threads


    test_url = get_test_url(rspamd_host, rspamd_port)
    
    run_tests(test_url=test_url,
              ham_location=args.ham,
              spam_location=args.spam,
              no_of_threads=no_of_threads)

    write_test_results(output_file, test_results)

    
if __name__ == "__main__":
    main()
