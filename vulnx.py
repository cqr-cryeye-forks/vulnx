# !/usr/bin/env python

from __future__ import (absolute_import, division, print_function)

import json
import pathlib
from typing import Final

"""
The vulnx main part.
Author: anouarbensaad
Desc  : CMS-Detector and Vulnerability Scanner & exploiter
Copyright (c)
See the file 'LICENSE' for copying permission
"""

from modules.detector import CMS
from modules.dorks.engine import Dork
from modules.dorks.helpers import DorkManual
from modules.cli.cli import CLI
from common.colors import red, green, bg, G, R, W, Y, G, good, bad, run, info, end, que, bannerblue2

from common.requestUp import random_UserAgent
from common.uriParser import parsing_url as hostd
from common.banner import banner

import sys
import argparse
import re
import os
import socket
import common
import warnings
import signal
import requests

HEADERS = {
    'User-Agent': random_UserAgent(),
    'Content-type': '*/*',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'keep-alive',
}

warnings.filterwarnings(
    action="ignore", message=".*was already imported", category=UserWarning)
warnings.filterwarnings(action="ignore", category=DeprecationWarning)


# cleaning screen

# banner()

def parser_error(errmsg):
    print("Usage: python " + sys.argv[0] + " [Options] use -h for help")
    print(R + "Error: " + errmsg + W)
    sys.exit()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.error = parser_error
    parser.add_argument('--url', help="url target to scan or domain")
    parser.add_argument(
        '--dorks', help='search webs with dorks', dest='dorks', type=str)
    parser.add_argument(
        '--output', help='specify output directory')
    parser.add_argument('--number-pages',
                        help='search dorks number page limit', dest='numberpage', type=int)
    # parser.add_argument('--input', help='specify input file of domains to scan', dest='input_file', required=False)
    parser.add_argument('--dork-list', help='list names of dorks exploits', dest='dorkslist',
                        choices=['wordpress', 'prestashop', 'joomla', 'lokomedia', 'drupal', 'all'])
    parser.add_argument('--ports', help='ports to scan',
                        dest='scanports', type=int)
    # Switches
    parser.add_argument('--exploit', help='searching vulnerability & run exploits',
                        dest='exploit', action='store_true')
    parser.add_argument('--it', help='interactive mode.',
                        dest='cli', action='store_true')

    parser.add_argument('--cms', help='search cms info[themes,plugins,user,version..]',
                        dest='cms', action='store_true')

    parser.add_argument('--web-info', help='web informations gathering',
                        dest='webinfo', action='store_true')
    parser.add_argument('--domain-info', help='subdomains informations gathering',
                        dest='subdomains', action='store_true')
    parser.add_argument('--dns', help='dns informations gatherings',
                        dest='dnsdump', action='store_true')

    return parser.parse_args()


# args declaration
args = parse_args()
output: str = args.output
url = args.url
# input_file = args.input_file
warnings.filterwarnings('ignore')


def write_json(output):
    MAIN_DIR: Final[pathlib.Path] = pathlib.Path(__file__).parent
    output_json: str = MAIN_DIR / output

    result = CMS(url)
    data = result.global_cms()

    with open(output_json, "w") as jf:
        json.dump(data, jf, indent=2)


def detection():
    instance = CMS(
        url,
        headers=HEADERS,
        exploit=args.exploit,
        domain=args.subdomains,
        webinfo=args.webinfo,
        serveros=True,
        cmsinfo=args.cms,
        dnsdump=args.dnsdump,
        port=args.scanports
    )
    instance.instanciate()


def dork_engine():
    if args.dorks:
        DEngine = Dork(
            exploit=args.dorks,
            headers=HEADERS,
            pages=(args.numberpage or 1)
        )
        DEngine.search()


def dorks_manual():
    if args.dorkslist:
        DManual = DorkManual(
            select=args.dorkslist
        )
        DManual.list()


def interactive_cli():
    if args.cli:
        cli = CLI(headers=HEADERS)
        cli.general("")


def signal_handler(signal, frame):
    print("%s(ID: {}) Cleaning up...\n Exiting...".format(signal) % (W))
    exit(0)


signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":

    dork_engine()
    dorks_manual()
    interactive_cli()

    if url:
        root = url
        if root.startswith('http://'):
            url = root
        elif root.startswith('https://'):
            url = root.replace('https://', 'http://')
        else:
            url = 'http://' + root
            print(url)
        detection()

    write_json(output)

    # if input_file:
    #     with open(input_file,'r') as urls:
    #         u_array = [url.strip('\n') for url in urls]
    #         try:
    #             for url in u_array:
    #                 root = url
    #             #url condition entrypoint
    #                 if root.startswith('http'):
    #                     url = root
    #                 else:
    #                     url = 'http://'+root
    #                 detection()
    #                 urls.close()
    #         except Exception as error:
    #             print('error : '+error)
