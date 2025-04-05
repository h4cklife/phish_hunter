#!venv/bin/python
# -*- coding: utf-8 -*-
import sys
from libs.predictor import Predictor
from libs.features import FeatureExtraction
import argparse
from time import sleep
from terminaltexteffects.effects.effect_decrypt import Decrypt

p = Predictor()

links = [
    'https://www.pkobp.pl/',
    'https://www.dskdirect.bg/page/default.aspx?xml_id=/bg-BG/.login',
    'https://mobilephotokiosk.app:443/view/1337',
    'https://podrozklienta.online/#/app/accept-invitation/emilia.sliwoska@pkobp.pl/1733303090/3xQuib5rvnf_IgW6EvXmVEjNKO4GgvOKapilH9bwAOw~7hCMWXlKgRrv6QPjpqmsyz5P_4RWBKN1mJgtPJiUNRA~',
    'https://wordpress.com/support/domains/',
    'https://lbpiaccess.com',
    'https://104.208.244.222/',
    'https://eniplenitude.com/my-eni',
    'https://ebio.gg/@meandyouxq',
    'https://explorer.walletconnect.com/',
    'https://www.autenticacao.gov.pt/',
    'https://ebanking.itauprivatebank.com/',
    'https://cloudflare-ipfs.org',
    'https://www.economist.com/',
    'https://www.nabtrade.com.au/',
    'https://paypay.ne.jp:443/',
    'https://www.truist.com/fraud-and-security',
    'https://releases.jquery.com/'

        ]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='phish_hunter',
        description='Analyze a URL to determine if it may be a Phishing site')

    parser.add_argument('-u', '--url')
    parser.add_argument('-r', '--run_internal_links', action='store_true')
    parser.add_argument('-a', '--append_dataset')
    parser.add_argument('-b', '--banner', action='store_true')

    args = parser.parse_args()

    if args.banner:
        effect = Decrypt("""
###############################################################################################################################################
░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓███████▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░▒▓████████▓▒░▒▓████████▓▒░▒▓███████▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
░▒▓███████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓██████▓▒░░▒▓████████▓▒░      ░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓██████▓▒░ ░▒▓███████▓▒░
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░

                  ░▒▓██████▓▒░░▒▓███████▓▒░▒▓████████▓▒░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓██████▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓█▓▒░
                 ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░
                 ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░
                 ░▒▓████████▓▒░▒▓███████▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░▒▓██████▓▒░ ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░
                 ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░
                 ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░
                 ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓██████▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░

 ░▒▓█▓▒░▒▓███████▓▒░▒▓████████▓▒░▒▓████████▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓██████▓▒░░▒▓████████▓▒░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓████████▓▒░
 ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░
 ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░
 ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓██████▓▒░ ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒▒▓███▓▒░▒▓██████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓██████▓▒░
 ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░
 ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░
 ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓████████▓▒░▒▓████████▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓██████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓████████▓▒░
###############################################################################################################################################
              ____   ______ _    __ ______ __    ____   ____   ______ ____     ____ __  __   ______ ___   ______ ___     __
             / __ \ / ____/| |  / // ____// /   / __ \ / __ \ / ____// __ \   / __ )\ \/ /  / ____//   | /_  __//   |   / /
            / / / // __/   | | / // __/  / /   / / / // /_/ // __/  / / / /  / __  | \  /  / /_   / /| |  / /  / /| |  / /
           / /_/ // /___   | |/ // /___ / /___/ /_/ // ____// /___ / /_/ /  / /_/ /  / /  / __/  / ___ | / /  / ___ | / /___
          /_____//_____/   |___//_____//_____/\____//_/    /_____//_____/  /_____/  /_/  /_/    /_/  |_|/_/  /_/  |_|/_____/
                                                                                                                AKA h4cklife
          ##################################################################################################################

          """)
        with effect.terminal_output() as terminal:
            for frame in effect:
                terminal.print(frame)

    if args.url is None and args.run_internal_links is None:
        parser.print_help()
        sys.exit(1)

    if args.url and not args.run_internal_links:
        fe = FeatureExtraction(args.url)

        feature_array = fe.getFeaturesArray()

        prediction = p.make_prediction(data=feature_array)

        result = None

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

    elif args.run_internal_links:
        # If no URL was passed and we got the run_internal_links switch
        # then process all the links in the array above
        count = 1
        for link in links:
            fe = FeatureExtraction(link)

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
            sleep(.5)

    else:
        parser.print_help()
        sys.exit(0)
