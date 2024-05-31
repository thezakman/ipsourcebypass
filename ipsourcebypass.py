#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ipsourcebypass.py
# Author             : Podalirius (@podalirius_)
# New Features       : TheZakMan (@TheZakMan)
# Date created       : 31 May 2024

import argparse
import os
import sys
from concurrent.futures import ThreadPoolExecutor
import requests
from rich.console import Console
from rich import box
from rich.table import Table
import json

VERSION = "1.4"

BYPASS_HEADERS = [
    {
        "header": "Access-Control-Allow-Origin",
        "description": "The Access-Control-Allow-Origin response header indicates whether the response can be shared with requesting code from the given origin.",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin"]
    },
    {
        "header": "Client-IP",
        "description": "",
        "references": [""]
    },
    {
        "header": "Forwarded",
        "description": "",
        "references": [""]
    },
    {
        "header": "Forwarded-For",
        "description": "",
        "references": [""]
    },
    {
        "header": "Forwarded-For-IP",
        "description": "",
        "references": [""]
    },
    {
        "header": "Origin",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Client-IP",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Forwarded",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Forwarded-By",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Forwarded-For",
        "description": "The X-Forwarded-For (XFF) request header is a de-facto standard header for identifying the originating IP address of a client connecting to a web server through a proxy server.",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For"]
    },
    {
        "header": "X-Forwarded-For-Original",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Forwarded-Host",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Forwarder-For",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Originating-IP",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Remote-Addr",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Remote-IP",
        "description": "",
        "references": [""]
    },
    {
        "header": "CF-Connecting-Ip",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Real-IP",
        "description": "",
        "references": [""]
    },
    {
        "header": "True-Client-IP",
        "description": "",
        "references": ["https://docs.aws.amazon.com/en_us/AmazonCloudFront/latest/DeveloperGuide/example-function-add-true-client-ip-header.html"]
    },
    {
        "header": "WL-Proxy-Client-IP",
        "description": "WebLogic Proxy Header",
        "references":["https://www.ateam-oracle.com/post/understanding-the-use-of-weblogic-plugin-enabled"]
    },
    {
        "header":"Proxy-Client-IP",
        "description": "No reference now, just very used",
        "references":[""]
    },
        {
        "header": "Cache_Info",
        "description": "",
        "references": [""]
    },
    {
        "header": "Cf_Connecting_Ip",
        "description": "",
        "references": [""]
    },
    {
        "header": "Client_Ip",
        "description": "",
        "references": [""]
    },
    {
        "header": "Client-Ip",
        "description": "",
        "references": [""]
    },
    {
        "header": "Coming_From",
        "description": "",
        "references": [""]
    },
    {
        "header": "Connect_Via_Ip",
        "description": "",
        "references": [""]
    },
    {
        "header": "Forward_For",
        "description": "",
        "references": [""]
    },
    {
        "header": "Forward-For",
        "description": "",
        "references": [""]
    },
    {
        "header": "Forwarded_For",
        "description": "",
        "references": [""]
    },
    {
        "header": "Forwarded_For_Ip",
        "description": "",
        "references": [""]
    },
    {
        "header": "Http-Client-Ip",
        "description": "",
        "references": [""]
    },
    {
        "header": "Http-Forwarded-For-Ip",
        "description": "",
        "references": [""]
    },
    {
        "header": "Http-Pc-Remote-Addr",
        "description": "",
        "references": [""]
    },
    {
        "header": "Http-Proxy-Connection",
        "description": "",
        "references": [""]
    },
    {
        "header": "Http-Url",
        "description": "",
        "references": [""]
    },
    {
        "header": "Http-Via",
        "description": "",
        "references": [""]
    },
    {
        "header": "Http-X-Forwarded-For-Ip",
        "description": "",
        "references": [""]
    },
    {
        "header": "Http-X-Imforwards",
        "description": "",
        "references": [""]
    },
    {
        "header": "Http-Xroxy-Connection",
        "description": "",
        "references": [""]
    },
    {
        "header": "Pc_Remote_Addr",
        "description": "",
        "references": [""]
    },
    {
        "header": "Pragma",
        "description": "",
        "references": [""]
    },
    {
        "header": "Proxy",
        "description": "",
        "references": [""]
    },
    {
        "header": "Proxy_Authorization",
        "description": "",
        "references": [""]
    },
    {
        "header": "Proxy_Connection",
        "description": "",
        "references": [""]
    },
    {
        "header": "Proxy-Host",
        "description": "",
        "references": [""]
    },
    {
        "header": "Proxy-Url",
        "description": "",
        "references": [""]
    },
    {
        "header": "Real-Ip",
        "description": "",
        "references": [""]
    },
    {
        "header": "Redirect",
        "description": "",
        "references": [""]
    },
    {
        "header": "Referer",
        "description": "",
        "references": [""]
    },
    {
        "header": "Referrer",
        "description": "",
        "references": [""]
    },
    {
        "header": "Refferer",
        "description": "",
        "references": [""]
    },
    {
        "header": "Remote_Addr",
        "description": "",
        "references": [""]
    },
    {
        "header": "Request-Uri",
        "description": "",
        "references": [""]
    },
    {
        "header": "Source-Ip",
        "description": "",
        "references": [""]
    },
    {
        "header": "Uri",
        "description": "",
        "references": [""]
    },
    {
        "header": "Url",
        "description": "",
        "references": [""]
    },
    {
        "header": "Via",
        "description": "",
        "references": [""]
    },
    {
        "header": "X_Cluster_Client_Ip",
        "description": "",
        "references": [""]
    },
    {
        "header": "X_Coming_From",
        "description": "",
        "references": [""]
    },
    {
        "header": "X_Delegate_Remote_Host",
        "description": "",
        "references": [""]
    },
    {
        "header": "X_Forwarded",
        "description": "",
        "references": [""]
    },
    {
        "header": "X_Forwarded_For",
        "description": "",
        "references": [""]
    },
    {
        "header": "X_Forwarded_For_Ip",
        "description": "",
        "references": [""]
    },
    {
        "header": "X_Imforwards",
        "description": "",
        "references": [""]
    },
    {
        "header": "X_Locking",
        "description": "",
        "references": [""]
    },
    {
        "header": "X_Looking",
        "description": "",
        "references": [""]
    },
    {
        "header": "X_Real_Ip",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Backend-Host",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Bluecoat-Via",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Cache-Info",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Custom-Ip-Authorization",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Forward-For",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Forwarded-Port",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Forwarded-Scheme",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Forwarded-Server",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Gateway-Host",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Host",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Http-Destinationurl",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Http-Host-Override",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Ip",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Original-Ip",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Original-Remote-Addr",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Original-Url",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Originally-Forwarded-For",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Proxy-Url",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Proxymesh-Ip",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Proxyuser-Ip",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-Rewrite-Url",
        "description": "",
        "references": [""]
    },
    {
        "header": "X-True-Ip",
        "description": "",
        "references": [""]
    },
    {
        "header": "Xonnection",
        "description": "",
        "references": [""]
    },
    {
        "header": "Xproxy",
        "description": "",
        "references": [""]
    },
    {
        "header": "Xroxy_Connection",
        "description": "",
        "references": [""]
    },
    {
        "header": "Zcache_Control",
        "description": "",
        "references": [""]
    }

]


def test_bypass(options, proxies, results, header_name, header_value, delay):
    http_headers = {h.split(':', 1)[0]: h.split(':', 1)[1].strip() for h in options.headers}
    http_headers[header_name] = header_value
    try:
        r = requests.get(
            url=options.url,
            # This is to set the client to accept insecure servers
            verify=options.verify,
            proxies=proxies,
            allow_redirects=options.redirect,
            # This is to prevent the download of huge files, focus on the request, not on the data
            stream=True,
            headers=http_headers
        )
    except requests.exceptions.ProxyError:
        print("[!] Invalid proxy specified")
        raise SystemExit
    if options.verbose:
        print("[!] Obtained results: [%d] length : %d bytes" % (r.status_code, len(r.content)))
    if options.save:
        if not os.path.exists("./results/"):
            os.makedirs("./results/", exist_ok=True)
        f = open("./results/%s.html" % header_name, "wb")
        f.write(r.content)
        f.close()
    results[header_name] = {
        "status_code": r.status_code,
        "length": len(r.text),
        "header": "%s: %s" % (header_name, header_value),
        "curl": "curl %s\"%s\" -H \"%s: %s\"" % (("-k " if not options.verify else ""), options.url, header_name, header_value)
    }
    time.sleep(delay)

def print_results(console, results, curl=False):
    if options.verbose:
        print("[>] Parsing & printing results")
    table = Table(show_header=True, header_style="bold blue", border_style="blue", box=box.SIMPLE)
    table.add_column("Length")
    table.add_column("Status code")
    table.add_column("Header")
    if curl:
        table.add_column("curl")

    # Choose colors for uncommon lengths
    lengths = [result[1]["length"] for result in results.items()]
    lengths = [(len([1 for result in results.items() if result[1]["length"] == l]), l) for l in list(set(lengths))]

    if len(lengths) == 2:
        for result in results.items():
            if result[1]["length"] == min(lengths)[1]:
                style = "green"
            elif result[1]["length"] == max(lengths)[1]:
                style = "red"
            if curl:
                table.add_row(str(result[1]["length"]), str(result[1]["status_code"]), result[1]["header"], result[1]["curl"], style=style)
            else:
                table.add_row(str(result[1]["length"]), str(result[1]["status_code"]), result[1]["header"], style=style)
    elif len(lengths) == 3:
        scale = ["red", "orange3", "green"]
        colors = {str(sorted(lengths, reverse=True)[k][1]): scale[k] for k in range(len(lengths))}
        for result in results.items():
            style = colors[str(result[1]["length"])]
            if curl:
                table.add_row(str(result[1]["length"]), str(result[1]["status_code"]), result[1]["header"], result[1]["curl"], style=style)
            else:
                table.add_row(str(result[1]["length"]), str(result[1]["status_code"]), result[1]["header"], style=style)
    elif len(lengths) == 4:
        scale = ["red", "orange3", "yellow3", "green"]
        colors = {str(sorted(lengths, reverse=True)[k][1]): scale[k] for k in range(len(lengths))}
        for result in results.items():
            style = colors[str(result[1]["length"])]
            if curl:
                table.add_row(str(result[1]["length"]), str(result[1]["status_code"]), result[1]["header"], result[1]["curl"], style=style)
            else:
                table.add_row(str(result[1]["length"]), str(result[1]["status_code"]), result[1]["header"], style=style)
    else:
        for result in results.items():
            style = "orange3"
            if curl:
                table.add_row(str(result[1]["length"]), str(result[1]["status_code"]), result[1]["header"], result[1]["curl"], style=style)
            else:
                table.add_row(str(result[1]["length"]), str(result[1]["status_code"]), result[1]["header"], style=style)
    console.print(table)

banner = '''
┳┏┓┏┓         ┳┓        
┃┃┃┗┓┏┓┓┏┏┓┏┏┓┣┫┓┏┏┓┏┓┏┏
┻┣┛┗┛┗┛┗┻┛ ┗┗ ┻┛┗┫┣┛┗┻┛┛
by @podalirius_  ┛┛ ''' + VERSION

def parseArgs():
    print(banner,"\n")
    parser = argparse.ArgumentParser(description="This Python script can be used to test for IP source bypass using HTTP headers")
    parser.add_argument("url", help="e.g. https://example.com:port/path")
    parser.add_argument("-v", "--verbose", default=None, action="store_true", help='arg1 help message')
    parser.add_argument("-i", "--ip", dest="ip", required=True, help="IP to spoof.")
    parser.add_argument("-t", "--threads", dest="threads", action="store", type=int, default=5, required=False, help="Number of threads (default: 5)")
    parser.add_argument("-x", "--proxy", action="store", default=None, dest='proxy', help="Specify a proxy to use for requests (e.g., http://localhost:8080)")
    parser.add_argument("-k", "--insecure", dest="verify", action="store_false", default=True, required=False, help="Allow insecure server connections when using SSL (default: False)")
    parser.add_argument("-L", "--location", dest="redirect", action="store_true", default=False, required=False, help="Follow redirects (default: False)")
    parser.add_argument("-j", "--jsonfile", dest="jsonfile", default=None, required=False, help="Save results to specified JSON file.")
    parser.add_argument("-C", "--curl", dest="curl", default=False, required=False, action="store_true", help="Generate curl commands for each request.")
    parser.add_argument("-H", "--header", dest="headers", action="append", default=[], help='arg1 help message')
    parser.add_argument("-S", "--save", dest="save", default=False, required=False, action="store_true", help="Save all HTML responses.")
    parser.add_argument("-c", "--case", dest="case", action='store_true', default=False, required=False, help="Alternate Upper and Lower case (Case can matter with certains web servers)")
    parser.add_argument("-d", "--delay", dest="delay", action="store", type=int, default=0, required=False, help="Delay between requests in seconds (default: 0)")
    return parser.parse_args()

if __name__ == '__main__':
    options = parseArgs()
    try:
        console = Console()
        # Verifying the proxy option
        if options.proxy:
            try:
                proxies = {
                    "http": "http://" + options.proxy.split('//')[1],
                    "https": "http://" + options.proxy.split('//')[1]
                }
                if options.verbose:
                    print("[debug] Setting proxies to %s" % str(proxies))
            except (IndexError, ValueError):
                print("[!] Invalid proxy specified.")
                sys.exit(1)
        else:
            if options.verbose:
                print("[debug] Setting proxies to 'None'")
            proxies = None

        if not options.verify:
            # Disable warnings of insecure connection for invalid certificates
            requests.packages.urllib3.disable_warnings()
            # Allow use of deprecated and weak cipher methods
            requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
            try:
                requests.packages.urllib3.contrib.pyopenssl.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
            except AttributeError:
                pass

        results = {}

        # Waits for all the threads to be completed
        with ThreadPoolExecutor(max_workers=min(options.threads, len(BYPASS_HEADERS))) as tp:
            for bph in sorted(BYPASS_HEADERS, key=lambda x: x["header"]):
                if options.case:
                    tp.submit(test_bypass, options, proxies, results, bph["header"].upper(), options.ip, options.delay)
                    tp.submit(test_bypass, options, proxies, results, bph["header"].lower(), options.ip, options.delay)
                else:
                    tp.submit(test_bypass, options, proxies, results, bph["header"], options.ip, options.delay)

        # Sorting the results by method name
        results = {key: results[key] for key in sorted(results, key=lambda key: results[key]["length"])}

        # Parsing and print results
        print_results(console, results, curl=options.curl)

        # Export to JSON if specified
        if options.jsonfile is not None:
            with open(options.jsonfile, "w") as f:
                f.write(json.dumps(results, indent=4) + "\n")

    except KeyboardInterrupt:
        print("[+] Terminating script...")
        raise SystemExit
