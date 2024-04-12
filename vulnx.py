# !/usr/bin/env python

from __future__ import (absolute_import, division, print_function)

import json
import pathlib
from typing import Final

from modules.dns_dump import all_data_1, all_data_2

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


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# # # # # # # # # # E X A M P L E - I N P U T - I N - C O N F I G U R A T I O N S # # # # # # # # # #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# --url afganii.fun --exploit --cms --domain-info --dns --output data.json --dork-list all --ports  #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

def parser_error(errmsg):
    print("Usage: python " + sys.argv[0] + " [Options] use -h for help")
    print(R + "Error: " + errmsg + W)
    sys.exit()


def signal_handler(signal, frame):
    print("%s(ID: {}) Cleaning up...\n Exiting...".format(signal) % (W))
    exit(0)


def main():
    HEADERS = {
        'User-Agent': random_UserAgent(),
        'Content-type': '*/*',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
    }

    parser = argparse.ArgumentParser()
    parser.error = parser_error

    parser.add_argument('--url', help="url target to scan")
    parser.add_argument('--dorks', help='search webs with dorks')
    parser.add_argument('--output', help='specify output directory')
    parser.add_argument('--number-pages', help='search dorks number page limit', dest='numberpage')
    # parser.add_argument('--inputfile', help='specify input file of domains to scan', required=False)
    parser.add_argument('--dorkslist', help='list names of dorks exploits',
                        choices=['wordpress', 'prestashop', 'joomla', 'lokomedia', 'drupal', 'all'])
    # Switches
    parser.add_argument('--ports', help='ports to scan', action='store_true')
    parser.add_argument('--it', help='interactive mode.', dest='cli', action='store_true')
    parser.add_argument('--web-info', help='web informations gathering', dest='webinfo', action='store_true')

    parser.add_argument('--exploit', help='searching vulnerability & run exploits', dest='exploit', action='store_true')
    parser.add_argument('--cms', help='search cms info[themes,plugins,user,version..]', dest='cms', action='store_true')
    parser.add_argument('--domain-info', help='subdomains informations gathering', dest='subdomains', action='store_true')
    parser.add_argument('--dns', help='dns informations gatherings', dest='dnsdump', action='store_true')

    args = parser.parse_args()

    url: str = args.url
    output: str = args.output

    dorks: str = args.dorks
    dorks_list: str = args.dorkslist
    cli: str = args.cli
    number_pages: int = args.numberpage
    # inputfile: str = args.inputfile
    ports: int = args.ports
    exploit: str = args.exploit
    subdomains: str = args.subdomains
    webinfo: str = args.webinfo
    cms: str = args.cms
    dnsdump: str = args.dnsdump

    MAIN_DIR: Final[pathlib.Path] = pathlib.Path(__file__).parent
    output_json: MAIN_DIR / output

    warnings.filterwarnings('ignore')

    signal.signal(signal.SIGINT, signal_handler)

    warnings.filterwarnings(
        action="ignore", message=".*was already imported", category=UserWarning)
    warnings.filterwarnings(action="ignore", category=DeprecationWarning)

    # dork_engine
    if dorks:
        DEngine = Dork(
            exploit=dorks,
            headers=HEADERS,
            pages=(number_pages or 1)
        )
        DEngine.search()
    # dorks_manual
    if dorks_list:
        DManual = DorkManual(
            select=dorks_list
        )
        DManual.list()
    # interactive_cli
    if cli:
        cli = CLI(headers=HEADERS)
        cli.general("")

    if url:
        root = url
        if root.startswith('http://'):
            url = root
        elif root.startswith('https://'):
            url = root.replace('https://', 'http://')
        else:
            url = 'http://' + root

    # detection
    instance = CMS(
        url,
        headers=HEADERS,
        exploit=exploit,
        domain=subdomains,
        webinfo=webinfo,
        serveros=True,
        cmsinfo=cms,
        dnsdump=dnsdump,
        port=ports
    )
    instance.instanciate()

    MAIN_DIR: Final[pathlib.Path] = pathlib.Path(__file__).parent
    output_json: str = MAIN_DIR / output

    from modules.scan_ports import port_data_info
    result = CMS(url)
    data = result.global_cms()
    data_list = []
    data_list.append(all_data_1())
    data_list.append(all_data_2())
    data.update({"data_list": data_list})
    data.update({"Ports": port_data_info})
    with open(output_json, "w") as jf:
        json.dump(data, jf, indent=2)
    # if inputfile:
    #     with open(inputfile, 'r') as urls:
    #         u_array = [url.strip('\n') for url in urls]
    #         try:
    #             for url in u_array:
    #                 root = url
    #                 # url condition entrypoint
    #                 if root.startswith('http'):
    #                     url = root
    #                 else:
    #                     url = 'http://' + root
    #                 instance = CMS(
    #                     url,
    #                     headers=HEADERS,
    #                     exploit=exploit,
    #                     domain=subdomains,
    #                     webinfo=webinfo,
    #                     serveros=True,
    #                     cmsinfo=cms,
    #                     dnsdump=dnsdump,
    #                     port=ports
    #                 )
    #
    #                 instance.instanciate()
    #                 urls.close()
    #         except Exception as e:
    #             print('Error : ', e)


if __name__ == "__main__":
    main()

