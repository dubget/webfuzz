#needs requests lib
#pip install requests
#usage: web_fuzz.py [-h] -u U -m M [-d D] [-f F] [-c C] [-t T] [-l L] [-x X] [-o O]
#optional arguments:
#  -h, --help  show this help message and exit
#  -u U        URL
#  -m M        Scan mode
#  -d D        Path to directory dictionary - Required for Mode 2 and 3
#  -f F        Path to filename dictionary - Required for Mode 3
#  -c C        Path to custom dictionary - Required for Mode 4
#  -t T        Time to delay between requests in ms - Optional - 100ms by default
#  -l L        Max length of brute force - Required for Mode 1
#  -x X        File extension - Optional
#  -o O        Path of output file - Optional - Saves to fuzz_result.txt by default


#Example usage
#mode 1 - bruteforce - no extenstion | Format: http://URL/guess
#web_fuzz.py -u http://127.0.0.1:8000 -m 1 -l 5 -t 150 -o output.txt

#mode 1 - bruteforce - with extension | Format: http://URL/guess.extension
#web_fuzz.py -u  http://127.0.0.1:8000 -m 1 -l 5 -t 150 -x .html -o output.txt

#mode 2 - dir scan from dictionary | Format: http://URL/dir/dir/dir/...
#web_fuzz.py -u  http://127.0.0.1:8000 -m 2 -d dirs.txt -t 500 -o output.txt

#mode 3 - dir and filename dictonary scan | Format: http://URL/dir/filename
#web_fuzz.py -u  http://127.0.0.1:8000 -m 3 -d dirs.txt -f filenames.txt -t 150 -o output.txt

#mode 3 - dir and filename dictonary scan with extension | Format: http://URL/dir/filename.extension
#web_fuzz.py -u  http://127.0.0.1:8000 -m 3 -d dirs.txt -f filenames.txt -t 150 -x .html -o output.txt

#mode 4 - Custom dictionary scan | Format: http://URL/custom
#web_fuzz.py -u  http://127.0.0.1:8000 -m 4 -c custom.txt -t 150 -o output.txt

#mode 4 - Custom dictionary scan | Format: http://URL/custom.extension
#web_fuzz.py -u  http://127.0.0.1:8000 -m 4 -c custom.txt -t 500 -x.html -o output.txt


import requests
import time
import argparse
import itertools
import string
import sys
import os


#Brute force scan with option to add extension
def fuzz_file_brute(url, length, delay, extension, output_file):
    output = open(output_file, "w+")
    full_url = ''
    largest_len = 0
    for attempt in bruteforce(string.ascii_lowercase, length):
        full_url = '{}/{}{}'.format(url, attempt, extension)
        r = requests.get(full_url)
    
        if len(full_url) > largest_len:
            largest_len = len(full_url)
            spacing = 0
        else:
            spacing = largest_len - len(full_url)
            spacing += 4
        print('{}{}'.format(full_url, ' ' * (spacing)), end='\r')
        if (r.status_code != 404):
            result = '{} {}'.format(str(r.status_code), full_url)
            print ('{}{}'.format(result, ' ' * spacing, end=''))
            output.write('{}\n'.format(result))
        time.sleep(delay)
    print (' ' * (largest_len + 4))
    print ('SCAN COMPLETE!')
    output.close()
        
        
#SOURCE: https://stackoverflow.com/questions/11747254/python-brute-force-algorithm           
from itertools import chain, product
def bruteforce(charset, maxlength):
    return (''.join(candidate)
        for candidate in chain.from_iterable(product(charset, repeat=i)
        for i in range(1, maxlength + 1)))    


#Dictionary Dir Scan - Scan format: http://URL/dir/dir/dir...
def fuzz_dirs(url, dir_file, delay, extension, output_file):
    output = open(output_file, "w+")
    list_dir = FileToList(dir_file)
   
    largest_len = 0
    url_list = [url]
    while len(url_list) > 0:
        list_found = []
        for prefix in url_list:
            for suffix in list_dir:
                full_url = '{}/{}/'.format(prefix, suffix)
                r = requests.get(full_url)
            
                if len(full_url) > largest_len:
                    largest_len = len(full_url)
                    spacing = 0
                else:
                    spacing = largest_len - len(full_url)
                    spacing += 4
                print('{}{}'.format(full_url, ' ' * (spacing)), end='\r')
                if (r.status_code != 404):
                    result = '{} {}'.format(str(r.status_code), full_url)
                    print ('{}{}'.format(result, ' ' * spacing, end=''))
                    output.write('{}\n'.format(result))
                    list_found.append(full_url.rstrip('/'))
                time.sleep(delay)
            url_list = list(list_found)
            
    print (' ' * (largest_len + 4))
    print ('SCAN COMPLETE!')
    output.close()

#Custom File - Scan format: http://URL/custom_suffix.optional_extension
def fuzz_custom(url, custom_file, delay, extension, output_file):
    output = open(output_file, "w+")
    list_custom = list_dir = FileToList(custom_file)
    full_url = ''
    largest_len = 0
    for suffix in list_custom:
        full_url = '{}/{}{}'.format(url, suffix, extension)
        r = requests.get(full_url)
    
        if len(full_url) > largest_len:
            largest_len = len(full_url)
            spacing = 0
        else:
            spacing = largest_len - len(full_url)
            spacing += 4
        print('{}{}'.format(full_url, ' ' * (spacing)), end='\r')
        if (r.status_code != 404):
            result = '{} {}'.format(str(r.status_code), full_url)
            print ('{}{}'.format(result, ' ' * spacing, end=''))
            output.write('{}\n'.format(result))
        time.sleep(delay)
    print (' ' * (largest_len + 4))
    print ('SCAN COMPLETE!')
    output.close()


def FileToList(file_path):
    ret_list = []
    file = open(file_path, 'r')
    for line in file:
        ret_list.append(line.strip())
    return ret_list
    

#Fuzzes in the format: URL/dir/file
def fuzz_dir_file(url, dir_file, page_file, delay, extension, output_file):
    output=open(output_file, 'w+')
    list_dirs = FileToList(dir_file)
    list_pages = FileToList(page_file)
    full_url = ''
    largest_len = 0
    for directory in list_dirs:
        for pages in list_pages:
            full_url = '{}/{}/{}{}'.format(url, directory, pages, extension)
            r = requests.get(full_url)
        
            if len(full_url) > largest_len:
                largest_len = len(full_url)
                spacing = 0
            else:
                spacing = largest_len - len(full_url)
                spacing += 4
            print('{}{}'.format(full_url, ' ' * (spacing)), end='\r')
            if (r.status_code != 404):
                result = '{} {}'.format(str(r.status_code), full_url)
                print ('{}{}'.format(result, ' ' * spacing, end=''))
                output.write('{}\n'.format(result))
            time.sleep(delay)
    print (' ' * (largest_len + 4))
    print ('SCAN COMPLETE!')
    output.close()




#Fuzzes in this format URL/dir/filename
def fuzz_dir_temp(url, list_dirs, list_files, delay, output_file):
    full_url = ''
    biggest = 0
    for suffix in list_custom:
        old_url_len = len(full_url)
        full_url = '{} {}/{}'.format(url, suffix)
        r = requests.get(full_url)
    
        if len(full_url) > biggest:
            biggest = len(full_url)
            spacing = 0
        else:
            spacing = biggest - len(full_url)
            
        print('{} {}'.format(full_url, ' ' * (spacing + 4)), end='\r')
        sys.stdout.flush()
        if (r.status_code == 200):
            print(full_url + ' ' * spacing + '\n', end='')
        time.sleep(delay)

    
if __name__ == "__main__":
    try:
        delay = 0.1
        output_file = 'fuzz_results.txt'
        extension = ''
        parser = argparse.ArgumentParser()
        parser.add_argument('-u', required=True, help='URL')
        parser.add_argument('-m', required=True, help='Scan mode')
        parser.add_argument('-d', required=False, help='Path to directory dictionary - Required for Mode 2 and 3')
        parser.add_argument('-f', required=False, help='Path to filename dictionary - Required for Mode 3')
        parser.add_argument('-c', required=False, help='Path to custom dictionary - Required for Mode 4')
        parser.add_argument('-t', required=False, help='Time to delay between requests in ms - Optional - 100ms by default')
        parser.add_argument('-l', required=False, help='Max length of brute force - Required for Mode 1')
        parser.add_argument('-x', required=False, help='File extension - Optional')
        parser.add_argument('-o', required=False, help='Path of output file - Optional - Saves to fuzz_result.txt by default')
        
        args = parser.parse_args()
        if (args.t != None):
                delay = (int(args.t) * 0.001)
        if (args.o != None):
                output_file = args.o
        if (args.x != None):
                extension = args.x

              
        if (args.m == '1' and args.l != None):
                fuzz_file_brute(args.u, int(args.l), delay, extension, output_file)
        elif (args.m == '2' and args.d != None):
            fuzz_dirs(args.u, args.d, delay, extension, output_file)
        elif (args.m == '3' and args.d != None and args.f !=None):
            fuzz_dir_file(args.u, args.d, args.f, delay, extension, output_file)
        elif (args.m == '4' and args.c != None):
            fuzz_custom(args.u, args.c, delay, extension, output_file)
        else:
            print('Error! Please check if arguments are correct.')
    except KeyboardInterrupt:
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
        
        
        
    
