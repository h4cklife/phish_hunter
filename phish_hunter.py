#!venv/bin/python
# -*- coding: utf-8 -*-

import sys
import argparse
import warnings
from libs.predictor import Predictor
from libs.features_v1 import FeatureExtractionV1
from time import sleep
from terminaltexteffects.effects.effect_print import Print
from libs.data_utils import colors, blacklist_chars, get_dns_records, get_host_domain, get_root_domain, is_domain_on_hold, write_to_file

warnings.filterwarnings("ignore")

p = Predictor()

legit = [
    # Legitmate == -1
    ]

phish = [
    # phish == 1
    ]


links = []

for i in legit:
    links.append(i) 

for i in phish:
    links.append(i) 

#print(links)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='phish_hunter',
        description='Analyze a URL to determine if it may be a Phishing site')

    parser.add_argument('-u', '--url', help="URL to check")
    parser.add_argument('-r', '--run_internal_links', action='store_true', help="Run aginst the hardcoded URLs")
    parser.add_argument('-a', '--append_dataset', help="Append the result to the dataset for extended training")
    parser.add_argument('-nb', '--no_banner', help="No banner when starting", action='store_true')

    args = parser.parse_args()

    if not args.no_banner:
        effect = Print("""
  \\_____)\\_____
  /--v____ __`<  Phish Hunter Artifical Intelligence version 1.00        
          )/     Chomp ChOmP CHOMP     
          '
          """)
        with effect.terminal_output() as terminal:
            for frame in effect:
                terminal.print(frame)

    if args.url is None and args.run_internal_links is None:
        parser.print_help()
        sys.exit(1)

    if args.url and not args.run_internal_links:
        dns_result = get_dns_records(get_host_domain(args.url), 'A')
        domain_on_hold = is_domain_on_hold(get_root_domain(args.url))

        if dns_result != 'nxdomain' and dns_result != 'timeout' and dns_result is not None and not domain_on_hold:
            fe = FeatureExtractionV1(args.url)

            feature_array = fe.getFeaturesArray()

            prediction = p.make_prediction(data=feature_array)

            result = None

            count = 0

            if prediction is True:
                print(f"[*] {count} - {args.url} is PHISH: {prediction}")
                result = 1
            else:
                print(f"[-] {count} - {args.url} is PHISH: {prediction}")
                result = -1

            # If requested : add new data to the dataset for future training purposes
            if args.append_dataset:
                feature_array.append(result)
                fe.append_dataset(filename=args.append_dataset, new_row=feature_array)
        else:
            print(f"[*] {args.url} is offline")

    elif args.run_internal_links:
        # If no URL was passed and we got the run_internal_links switch
        # then process all the links in the array above
        count = 1
        for link in links:
            dns_result = get_dns_records(get_host_domain(link), 'A')
            domain_on_hold = is_domain_on_hold(get_root_domain(link))

            if dns_result != 'nxdomain' and dns_result != 'timeout' and dns_result is not None and not domain_on_hold:
                fe = FeatureExtractionV1(link)

                feature_array = fe.getFeaturesArray()

                prediction = p.make_prediction(data=feature_array)

                result = None

                if prediction is True:
                    print(f"[*] {count} - {link} is PHISH: {prediction}")
                    result = 1
                else:
                    print(f"[-] {count} - {link} is PHISH: {prediction}")
                    result = -1

                # If requested : add new data to the dataset for future training purposes
                if args.append_dataset:
                    feature_array.append(result)
                    fe.append_dataset(filename=args.append_dataset, new_row=feature_array)

                count += 1
                sleep(.1)
            else:
                print(f"[*] {link} is offline")

    else:
        parser.print_help()
        sys.exit(0)
