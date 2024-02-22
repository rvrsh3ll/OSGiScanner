#!/usr/bin/python3
import requests
from urllib3.exceptions import InsecureRequestWarning
import ipcalc
import argparse
import logging
from threading import Thread
import queue

def Main():
    # Script argument parsing
    parser = argparse.ArgumentParser(description='A script to identify OSGi Consoles')
    parser.add_argument('--cidr', type=str, metavar='CIDR', nargs=1, help='CIDR notation i.e 192.168.1.10/24', required=False)
    parser.add_argument('--host', type=str, help="A single hostname or ip to scan", required=False)
    parser.add_argument('--hostFile', type=str, help="Hostname list in a file", required=False)
    parser.add_argument('--cidrFile', type=str, help="CIDR list in a file", required=False)
    parser.add_argument('--port', type=int, help='Port number', required=True)
    parser.add_argument('--ssl', action='store_true',required=False)
    parser.add_argument('--username', type=str, help='Username for authentication', required=False)
    parser.add_argument('--password', type=str, help='Password for authentication', required=False)
    parser.add_argument('--threads', type=int, default=10, help='Number of Threads', required=False)
    parser.add_argument('--outfile', action='store', default='osgi_scanner.log', help='Log results to this file')
    parser.add_argument('--verbose', help="Be verbose", action="store_true")
    args = parser.parse_args()

    # Set the queue
    q = queue.Queue()
  
    # Common OSGi Paths
    uris = ["/", "/system", "/console/", "/system/console"]
    protocol = "s" if args.ssl else ""
    results = []
    # Define logging stuff   
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    # create a file handler
    handler = logging.FileHandler(args.outfile)
    handler.setLevel(logging.INFO)
    # add the handlers to the logger
    logger.addHandler(handler)
    # create a logging format
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    handler.setFormatter(formatter)

    if args.cidr:
        for ip in ipcalc.Network(args.cidr[0]):
            for uri in uris:
                target = f"http{protocol}://{ip}:{args.port}{uri}"
                q.put(target)
    elif args.host:
        for uri in uris:
            target = f"http{protocol}://{args.host}:{args.port}{uri}"
            q.append(target)
    elif args.hostFile:
        with open(args.hostFile, 'r') as hostFile:
            hosts = hostFile.readlines()
        for host in hosts:
            host = host.strip()
            for uri in uris:
                target = f"http{protocol}://{host}:{args.port}{uri}"
                q.put(target)
    elif args.cidrFile:
        with open(args.cidrFile, 'r') as cidrFile:
            cidrs = cidrFile.readlines()
        for cidr in cidrs:
            cidr = cidr.strip()
            for ip in ipcalc.Network(cidr):
                for uri in uris:
                    target = f"http{protocol}://{ip}:{args.port}{uri}"
                    q.put(target)
    # Start
    threads = []
    for i in range(args.threads):
            worker = Thread(target=ScanIP,args=(args.username,args.password,args.verbose,q,results,),daemon=True)
            worker.start()
            threads.append(worker)

    # Join queue
    q.join()

    # Log Results
    for result in (results):
        print(result)
        logger.info(result)

def ScanIP(username,password,verbose,q,results):

    while True:

        # Get target
        target = q.get()
        if target is None:
            break
        # Handle SSL/TLS Errors
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
        # Begin the search
        try:
            if verbose:
                print("[*] Trying " + target)
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64; Trident/7.0; rv:11.0) like Geckos'}
            response = requests.get(target, headers=headers, timeout=4, verify=False)
            response.raise_for_status()
        except (requests.exceptions.RequestException) as e:
            if hasattr(e.response, 'status_code'):
                if e.response.status_code == 401:
                    # Check the basic auth header for OSGi
                    if ("OSGi" in e.response.headers['www-authenticate']):
                        results.append("[!] Found OSGi Console at {}".format(target))
                        # Attempt auth if a username is provided
                        if username:
                            try:
                                response = requests.get(target, headers=headers, auth=(username, password), timeout=4, verify=False)
                                response.raise_for_status()
                                if response.status_code == 200:
                                    results.append("[+] Successful login to OSGi Console at " + target)
                            except (requests.exceptions.RequestException) as e:
                                pass
        q.task_done()

if __name__ == "__main__":
    Main()