import os

def get_all_filenames(location):
    ''' Recursively gets a list of  all file names'''
    
    files = []
    
    for root, directories, filenames in os.walk(location):
        for filename in filenames:
            if not filename.startswith('.'):
                files.append(os.path.join(root, filename))

    return files

