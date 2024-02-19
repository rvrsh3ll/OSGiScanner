#!/usr/bin/python3
import requests
from urllib3.exceptions import InsecureRequestWarning
import ipcalc
import argparse
import logging
import threading
import http.client
import sys

class ScanIP(threading.Thread):
    def __init__(self, target, username, password, outfile, verbose):
        threading.Thread.__init__(self)
        self.target = target
        self.username = username
        self.password = password
        self.outfile = outfile
        self.verbose = verbose

    def run(self):
        # Set Logging
        # Define logging stuff
        logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        handlers=[logging.FileHandler(self.outfile), logging.StreamHandler(sys.stdout)],
        )
        # Handle SSL/TLS Errors
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

        # Begin the search
        try:
            if self.verbose:
                logging.info("[*] Trying " + self.target)
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64; Trident/7.0; rv:11.0) like Geckos'}
            response = requests.get(self.target, headers=headers, timeout=4, verify=False)
            response.raise_for_status()
        except (requests.exceptions.RequestException, http.client.BadStatusLine) as e:
            if hasattr(e.response, 'status_code'):
                if e.response.status_code != 401:
                    pass
                else:
                    # Check the basic auth header for OSGi
                    if ("OSGi" in e.response.headers['www-authenticate']):
                        logging.info("[!] Found OSGi Console at " + self.target)
                        # Attempt auth if a username is provided
                        if self.username:
                            try:
                                response = requests.get(self.target, headers=headers, auth=(self.username, self.password), timeout=4, verify=False)
                                response.raise_for_status()
                                if response.status_code == 200:
                                    logging.info("[+] Successful login to OSGi Console at " + self.target)
                            except (requests.exceptions.RequestException, http.client.BadStatusLine) as e:
                                pass
                        else:
                            pass
def Main():
    # Script argument parsing
    parser = argparse.ArgumentParser(description='A script to identify OSGi Consoles')
    parser.add_argument('--cidr', type=str, metavar='CIDR', nargs=1, help='CIDR notation i.e 192.168.1.10/24', required=False)
    parser.add_argument('--hosts', type=str, help="Hostname List", required=False)
    parser.add_argument('--port', type=int, help='Port number', required=True)
    parser.add_argument('--ssl', action='store_true',required=False)
    parser.add_argument('--username', type=str, help='Username for authentication', required=False)
    parser.add_argument('--password', type=str, help='Password for authentication', required=False)
    parser.add_argument('--threads', type=int, default=10, help='Number of Threads', required=False)
    parser.add_argument('--outfile', action='store', default='osgi_scanner.log', help='Log results to this file')
    parser.add_argument('--verbose', help="Be verbose", action="store_true")
    args = parser.parse_args()
    # Common OSGi Paths
    uris = ["/","/system","/console/","/system/console"]
    protocol = "s" if args.ssl == True else ""
    targets = []
    if args.cidr:
        for ip in ipcalc.Network(args.cidr[0]):
            for uri in uris:
                target = f"http{protocol}://{ip}:{args.port}{uri}"
                targets.append(target)
    elif args.hosts:
        with open(args.hosts,'r') as hostfile:
            hosts = hostfile.readlines()
        for host in hosts:
            for uri in uris:
                target = f"http{protocol}://{host}:{args.port}{uri}"
                targets.append(target)
    threads = []
    for target in targets:
        t = ScanIP(target, args.username, args.password, args.outfile,args.verbose)
        threads.append(t)

    for t in threads:
        t.start()

    for t in threads:
        t.join()

if __name__ == "__main__":
    Main()
