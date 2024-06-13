# !/usr/bin/env python

from __future__ import (absolute_import, division, print_function)

import json
import pathlib
import time
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
# from common.banner import banner

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
    exit("parser_error")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', help="url target to scan")
    parser.add_argument(
        '-D', '--dorks', help='search webs with dorks', dest='dorks', type=str)
    # parser.add_argument(
    #     '-o', '--output', help='specify output directory', required=False)
    parser.add_argument('-n', '--number-pages',
                        help='search dorks number page limit', dest='numberpage', type=int)
    parser.add_argument('-i', '--input', help='specify input file of domains to scan', dest='input_file',
                        required=False)
    parser.add_argument('-l', '--dork-list', help='list names of dorks exploits', dest='dorkslist',
                        choices=['wordpress', 'prestashop', 'joomla', 'lokomedia', 'drupal', 'all'])
    parser.add_argument('-p', '--ports', help='ports to scan',
                        dest='scanports', action='store_true')
    # Switches
    parser.add_argument('-e', '--exploit', help='searching vulnerability & run exploits',
                        dest='exploit', action='store_true')
    parser.add_argument('--output', help='Output file, save to json format, Example=data.json')

    parser.add_argument('--it', help='interactive mode.',
                        dest='cli', action='store_true')

    parser.add_argument('--cms', help='search cms info[themes,plugins,user,version..]',
                        dest='cms', action='store_true')

    parser.add_argument('-w', '--web-info', help='web informations gathering',
                        dest='webinfo', action='store_true')
    parser.add_argument('-d', '--domain-info', help='subdomains informations gathering',
                        dest='subdomains', action='store_true')
    parser.add_argument('--dns', help='dns informations gatherings',
                        dest='dnsdump', action='store_true')

    return parser.parse_args()


# args declaration
args = parse_args()
# url arg
url = args.url
# input_file
input_file = args.input_file
# Disable SSL related warnings
warnings.filterwarnings('ignore')
output = args.output


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
    try:
        res1, res2, res3 = instance.instanciate()
    except Exception as e:
        print(e)
        if str(e) == "[Errno -2] Name or service not known" or "HTTPSConnectionPool" in str(e):
            return {"Error -2": "Name or service not known, use other port to scan"}, {}, {}
        return {}, {}, {}
    return res1, res2, res3


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
    exit()


signal.signal(signal.SIGINT, signal_handler)


def has_port_ip(ip_with_port: str) -> bool:
    pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$")
    return bool(pattern.match(ip_with_port))


def has_port_http(url: str) -> bool:
    pattern = re.compile(r"^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+")
    return bool(pattern.match(url))


def get_port_ip(ip_with_port: str):
    match = ip_with_port.split(':')[-1]
    return match


def get_port_http(url: str):
    match = url.split(':')[-1]
    return match


if __name__ == "__main__":
    res1 = {}
    res2 = {}
    res3 = {}
    dork_engine()
    dorks_manual()
    interactive_cli()

    if url:

        print(has_port_ip(url))
        print(has_port_http(url))

        if has_port_ip(url):
            args.scanports = int(get_port_ip(url))
        elif has_port_http(url):
            args.scanports = int(get_port_http(url))

        print(args.scanports)

        root = url
        if root.startswith('http://'):
            url = root
        elif root.startswith('https://'):
            url = root
            # url = root.replace('https://', 'http://')
        else:
            url = 'https://' + root
            print(url)

        res1, res2, res3 = detection()
    print(res1, res2, res3)
    MAIN_DIR: Final[pathlib.Path] = pathlib.Path(__file__).parent
    output_json: Final[pathlib.Path] = MAIN_DIR / output

    from modules.scan_ports import port_data_info
    if res1 == {"Error -2": "Name or service not known, use other port to scan"}:
        data = {
            "Error": "Name or service not known, use other port to scan"
        }
    elif res1 == {} and res2 == {} and res3 == {}:
        data = {
            "Error": "VulnX failed to connect"
        }
    else:
        data = {
            "res1": res1,
            "res2": res2,
            "res3": res3,
            "Ports": port_data_info,
        }
    with open(output_json, "w") as jf:
        json.dump(data, jf, indent=2)
