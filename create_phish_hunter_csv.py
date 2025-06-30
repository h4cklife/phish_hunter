#!venv/bin/python
# -*- coding: utf-8 -*-

import sys
import argparse
from libs.features_v1 import FeatureExtractionV1
import warnings
import logging
import argparse
#import unicodedata
import kagglehub
#import keyboard
from libs.data_utils import colors, blacklist_chars, get_dns_records, get_host_domain, get_root_domain, is_domain_on_hold, write_to_file
from terminaltexteffects.effects.effect_print import Print

warnings.filterwarnings("ignore")

# Get the Paramiko logger
#paramiko_logger = logging.getLogger('paramiko')
#bs4_logger = logging.getLogger('bs4')

# Set the logging level to WARNING or higher
#paramiko_logger.setLevel(logging.WARNING)

# Alternatively, to disable all Paramiko logging:
# paramiko_logger.setLevel(logging.CRITICAL + 1) 
#bs4_logger.setLevel(logging.CRITICAL + 1)


def normalize_string(text):
    # Convert to lowercase
    text = text.lower()
    
    # Normalize Unicode
    #text = unicodedata.normalize('NFC', text)
    
    # Remove punctuation
    #text = re.sub(r'[^\w\s]', '', text)
    
    # Remove extra whitespace
    #text = " ".join(text.split())

    return text

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                    prog='create_phish_hunter_csv',
                    description='Create the dataset.csv from provided URLS for training Phish Hunter.')
    parser.add_argument('-l', '--limit', help='Limit the number of phish and non-phish results to use. i.e. 50 = 100')
    parser.add_argument('-i', '--input', help='The csv filename containing url,status')
    parser.add_argument('-o', '--output', help='The csv filename to output the dataset to', required=True)
    parser.add_argument('-a', '--append', help='Append to the output file. Don\'t write the header row')
    parser.add_argument('-d', '--download', action='store_true', help='Downloads lists from kagglehub and prints the paths')
    parser.add_argument('-nb', '--no_banner', action='store_true', help='No banner at startup')
    args = parser.parse_args()

    if not args.no_banner:
        effect = Print("""
  \\_____)\\_____
  /--v____ __`<  Phish hunter Artifical Intelligence version 1.00        
          )/     Dataset Creator      
          '
""")
        with effect.terminal_output() as terminal:
            for frame in effect:
                terminal.print(frame)
    else:
        print("Opintel Phish Hunter Dataset Creator v1.0.0")

    print("\nLoading input data for phish/legitimate website urls...")
    
    if args.download:
        path1 = kagglehub.dataset_download("taruntiwarihp/phishing-site-urls")
        path2 = kagglehub.dataset_download("harisudhan411/phishing-and-legitimate-urls")
        print(f"taruntiwarihp/phishing-site-urls: {path1}")
        print(f"harisudhan411/phishing-and-legitimate-urls: {path2}")

    phish_urls = [
    ]

    legitimate_urls = [
    ]

    with open(f"{args.input}", 'r') as csv_file:
        csv_lines = csv_file.readlines()
        for line in csv_lines:
            for char in blacklist_chars:
                if char in line:
                    continue

            line = line.strip()
            split_line = line.split(',')

            # Lines that don't have a phish/legitimate value
            if len(split_line) <= 1:
                continue

            # Lines that continue URLs with commas in them
            if len(split_line) >= 3:
                continue

            if split_line[0].strip().lower() == 'url' or \
                split_line[1].strip().lower() == 'status':
                continue
            url = split_line[0].strip()
            status = split_line[1].strip()

            try:
                if int(status) == -1: # was 1 (good)
                    legitimate_urls.append(url)
                elif int(status) == 1: # was 0 (bad)
                    phish_urls.append(url)
            except:
                pass

            try:
                if status == 'good' :
                    legitimate_urls.append(url)
                elif status == 'bad':
                    phish_urls.append(url)
            except:
                pass

    headers = ['having_ip_address', 'url_length', 'url_depth', 'shortining_service', 'having_at_symbol', 'double_slash_redirecting', 'prefix_suffix', 
                'having_sub_domain', 'sslfinal_state', 'domain_registration_length', 'favicon', 'port', 'https_token', 'request_url', 'url_of_anchor', 
                'links_in_tags', 'sfh', 'submitting_to_email', 'abnormal_url', 'redirect', 'on_mouseover', 'rightclick', 'popupwindow', 'iframe', 'age_of_domain', 
                'dnsrecord', 'malicious_content', 'safe_tld', 'screenshot_ocr', 'result']
            
    count = 0

    print("Creating the Phish Hunter dataset...")
    print(f"Loading {len(phish_urls)} phishing URLs...")
    print(f"Loading {len(legitimate_urls)} legitimate URLs...")

    if not args.append:
        write_to_file(args.output, headers)

    for index, value in enumerate(phish_urls):
        phish_url = phish_urls[index]
        legitimate_url = legitimate_urls[index]

        # Add a phish to the prepared csv data
        try:
            print(f"Processing phish URL : {phish_url}")
            dns_result = get_dns_records(get_host_domain(phish_url), 'A')
            domain_on_hold = is_domain_on_hold(get_root_domain(phish_url))

            if dns_result != 'nxdomain' and dns_result != 'timeout' and dns_result is not None and not domain_on_hold:
                phish_fe = FeatureExtractionV1(url=phish_url)
                phish_results = phish_fe.getFeaturesArray()
                phish_results.append("1")
                write_to_file(args.output, phish_results)
                count += 1
            else:
                print(f"{colors.FAIL}Phish URL - Offline Domain : {phish_url}{colors.ENDC}")
        except Exception as exp:
            print(f"{colors.FAIL}{exp}{phish_url}{colors.ENDC}")
        except KeyboardInterrupt:
            answer = input("(S)kip or (E)xit?")
            if answer.lower() == "s":
                continue
            elif answer.lower() == "e":
                sys.exit()
            else:
                continue

        # Add a non-phish to the prepared csv data
        try:
            print(f"Processing legitmate URL : {legitimate_url}")
            dns_result = get_dns_records(get_host_domain(legitimate_url), 'A')
            domain_on_hold = is_domain_on_hold(get_root_domain(legitimate_url))

            if dns_result != 'nxdomain' and dns_result != 'timeout' and dns_result is not None and not domain_on_hold:
                legitimate_fe = FeatureExtractionV1(url=legitimate_url)
                legitimate_results = legitimate_fe.getFeaturesArray()
                legitimate_results.append("-1")
                write_to_file(args.output, legitimate_results)
                count += 1
            else:
                print(f"{colors.FAIL}Legitmate URL - Offline Domain : {legitimate_url}{colors.ENDC}")
        except Exception as exp:
            print(f"{colors.FAIL}{exp}{phish_url}{colors.ENDC}")
        except KeyboardInterrupt:
            answer = input("(S)kip or (E)xit?")
            if answer.lower() == "s":
                continue
            elif answer.lower() == "e":
                sys.exit()
            else:
                continue

        if args.limit:
            if count >= int(args.limit):
                break
    
    print(f"Phish Hunter's AI Training Data file '{args.output}' has been written successfully.")
