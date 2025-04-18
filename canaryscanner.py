# Canarytokens use datastreams to hide the callback URL for their tokens. With that, it prevents an individual (potentially the attacker) to use filtering binaries (e.g grep or xxd) to look embedded URLS 
# This works by spotting links that can be found on the canary token itself. It will look for data streams inside the document and attempt to decode it.
# AUTHOR: JR Dioca

import os
import zipfile
import re
import shutil
import sys
import zlib
from colorama import Fore, Style, init

# initialize colorama for coloring, you can comment this if dont want colorful outputs... <:
init()

def extract_urls_from_stream(stream):
    ''' decompress file with zlib to extract PDF stream 
    extract URLs from stream with regex'''
    try:
        decompressed_data = zlib.decompress(stream)
        return re.findall(b'https?://[^\s<>"\'{}|\\^`]+', decompressed_data)
    except zlib.error:
        return []

def process_pdf_file(pdf_path):
# find embedded URL from stream
    with open(pdf_path, 'rb') as file:
        content = file.read()
    
    streams = re.findall(b'stream[\r\n\s]+(.*?)[\r\n\s]+endstream', content, re.DOTALL)
    return [url for stream in streams for url in extract_urls_from_stream(stream)]

def scan_office_doc(file_path):
# scan MS Office files (only works on docx, xlsx, and Adobe PDF)
    temp_dir = "temp_office_extract"
    os.makedirs(temp_dir, exist_ok=True)
    suspicious = False
    url_pattern = re.compile(r'https?://\S+')
    safe_domains = {
        'schemas.openxmlformats.org',
        'schemas.microsoft.com',
        'purl.org',
        'w3.org'
    }

    try:
        # extract Office document contents
        with zipfile.ZipFile(file_path, 'r') as zf:
            zf.extractall(temp_dir)
        
        # scan extracted files
        for root, _, files in os.walk(temp_dir):
            for filename in files:
                file_path = os.path.join(root, filename)
                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()
                        for url in url_pattern.findall(content):
                            if not any(domain in url for domain in safe_domains):
                                # colors the URL output
                                print(f"URL FOUND : {Fore.RED}{url}{Style.RESET_ALL}")
                                suspicious = True
                except (IOError, UnicodeDecodeError):
                    continue
    except Exception as e:
        print(f"Error scanning {file_path}: {str(e)}")
    finally:
        # cleanup
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    return suspicious

def analyze_file(file_path):
    '''This is where the magic happens. THE MAIN ANALYSIS FUNCTION'''
    if file_path.lower().endswith(('.docx', '.xlsx')):
        return scan_office_doc(file_path)
    elif file_path.lower().endswith('.pdf'):
        if found_urls := process_pdf_file(file_path):
            for url in found_urls:
                # colors URL output
                print(f"URL FOUND: {Fore.RED}{url.decode('utf-8', 'ignore')}{Style.RESET_ALL}")
            return True
    return False

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} FILE_OR_DIRECTORY_PATH")
        sys.exit(1)

    target_path = sys.argv[1]

    if not os.path.exists(target_path):
        print(f"Path does not exist: {target_path}")
        return

    if os.path.isfile(target_path):
        # scan single file
        if analyze_file(target_path):
            print(f"{target_path} - {Fore.RED}SUSPICIOUS{Style.RESET_ALL}")
        else:
            print(f"{target_path} - {Fore.GREEN}CLEAN{Style.RESET_ALL}")
    else:
        # scan entire directory
        for root, _, files in os.walk(target_path):
            for filename in files:
                full_path = os.path.join(root, filename)
                if analyze_file(full_path):
                    print(f"{full_path} - {Fore.RED}SUSPICIOUS{Style.RESET_ALL}")
                else:
                    print(f"{full_path} - {Fore.GREEN}CLEAN{Style.RESET_ALL}")

if __name__ == "__main__":
    main()