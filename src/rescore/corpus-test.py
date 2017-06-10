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


test_queue = Queue()    # Each element is a tuple: (file_location, email_type)
                        # email_type is either "SPAM" or "HAM"
test_results = []


def get_all_filenames(location):
    ''' Recursively gets a list of  all file names'''
    
    files = []
    
    for root, directories, filenames in os.walk(location):
        for filename in filenames:
            if not filename.startswith('.'):
                files.append(os.path.join(root, filename))

    return files


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

            
def test_email(test_url):

    while True:

        file_location, email_type = test_queue.get()

        with open(file_location, 'r') as f:
            try:
                response = requests.post(test_url, data=f)
            except RequestException as err:
                print "Connection error."
                print err
            else:
                metrics = json.loads(response.text)["default"]

                symbols = get_symbols_from_response(metrics)

                test_results.append('{} {} {} {}'.format(basename(file_location),
                                                         email_type,
                                                         metrics['score'],
                                                         ' '.join(symbols)))
        test_queue.task_done()

        
def test_emails_from_dir(location, email_type):

    if email_type not in ['HAM', 'SPAM']:
        raise ValueError("Wrong email_type")
        return

    filenames = []
    
    if os.path.isdir(location):
        filenames = get_all_filenames(location) 
    else:
        filenames.append(location)

    for filename in filenames:
        test_queue.put((filename, email_type))

        
def write_test_results(output_file, test_results):

    with open(output_file, 'w') as out:
        out.write('\r\n'.join(test_results))
        

def run_tests(test_url, ham_location, spam_location, no_of_threads=2):

    threads = [Thread(target=test_email, args=(test_url, ))
               for _ in range(no_of_threads)]

    for thread in threads:
        thread.setDaemon(True)
        thread.start()

    if ham_location:
        test_emails_from_dir(ham_location, "HAM")
    if spam_location:
        test_emails_from_dir(spam_location, "SPAM")

    test_queue.join()


    return
    
    
def main():

    rspamd_host = "127.0.0.1"
    rspamd_port = 11333
    output_file = "results.log"
    no_of_threads = 2

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
                            help="number of threads to run tests",
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
