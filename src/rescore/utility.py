import os
import random

def get_all_filenames(location):
    ''' Recursively gets a list of  all file names'''
    
    files = []
    
    for root, directories, filenames in os.walk(location):
        for filename in filenames:
            if not filename.startswith('.'):
                files.append(os.path.join(root, filename))

    return files

def shuffle(X, y):

    combined = zip(X, y)

    random.shuffle(combined)

    X, y = zip(*combined)

    return X, y
