#!venv/bin/python
# -*- coding: utf-8 -*-
import sys
from libs.predictor import Predictor
from libs.features_v1 import FeatureExtractionV1
import json
import argparse


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                        prog='analyze_url',
                        description='Analyze a URL for debugging the Phish Hunter ML AI')

    parser.add_argument('-u', '--url')      # option that takes a value
    parser.add_argument('-a', '--array', action='store_true')
    parser.add_argument('-d', '--dict', action='store_true')
    parser.add_argument('-s', '--source', action='store_true')

    args = parser.parse_args()

    if args.url is None:
        parser.print_help()
        sys.exit(1)

    p = Predictor()

    print(f"Length of URL: {len(args.url)} : {args.url}")

    if args.array:
        fe = FeatureExtractionV1(args.url)
        print(fe.getFeaturesArray())
    elif args.dict:
        fe = FeatureExtractionV1(args.url)
        print(json.dumps(fe.getFeaturesDict(), indent=4))
    elif args.source:
        fe = FeatureExtractionV1(args.url)
        print(fe.getPageSource())
    else:
        fe = FeatureExtractionV1(args.url)
        print(json.dumps(fe.getFeaturesDict(), indent=4))

