import urllib2
import ssl
import ipcalc
import argparse
import logging
import Queue
import threading
import httplib


class ScanIP(threading.Thread):
    def __init__(self, queue, outfile):
        threading.Thread.__init__(self)
        self.queue = queue
        self.outfile = outfile
        while True:

            # Define loggin stuff
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            # create a file handler
            handler = logging.FileHandler(outfile)
            handler.setLevel(logging.INFO)
            # add the handlers to the logger
            logger.addHandler(handler)
            # create a logging format
            formatter = logging.Formatter('%(asctime)s - %(message)s')
            handler.setFormatter(formatter)
            if self.queue.empty():
                break

            # Bypass errors for bad SSL certs
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            # Read next target from the queue
            target = self.queue.get()

            # Begin the search
            try:
                print "[*] Trying " + target
                req = urllib2.Request(target)
                req.addheaders = [('User-Agent', 'Mozilla/5.0 (Windows NT 6.3; Win64; x64; Trident/7.0; rv:11.0) like Geckos')]
                handle = urllib2.urlopen(req, timeout=4, context=ctx)
                return true
            except (IOError, httplib.BadStatusLine) as e:
                if hasattr(e, 'code'):
                    if e.code != 401:
                        pass
                    else:
                        if ("OSGi" in e.headers['www-authenticate']):
                            print "[!] Found OSGi Console at " + target
                            logger.info("[!] Found OSGi Console at " + target)
                else:
                    pass
def Main():
    # Script argument parsing
    parser = argparse.ArgumentParser(description='A script to identify OSGi Consoles')
    parser.add_argument('--cidr', type=str, metavar='CIDR', nargs=1, help='CIDR notation i.e 192.168.1.10/24', required=True)
    parser.add_argument('--port', type=int, help='Port number', required=True)
    parser.add_argument('--threads', type=int, default=10, help='Number of Threads', required=False)
    parser.add_argument('--ssl', action='store_true', default=False, help='Enable SSL', required=False)
    parser.add_argument('--outfile', action='store', default='osgi_scanner.log', help='Log results to this file')
    args = parser.parse_args()
    
    # URI to the console. Default location.
    uri = '/system/console'
    if args.port == 443:
        protocol = "s"
    else:
        if args.ssl:
            protocol = "s"
        else:
            protocol = ""
            
    # Set the queue
    queue = Queue.Queue()

    for ip in ipcalc.Network(args.cidr[0]):
        target = "http" + str(protocol) + "://" + str(ip) + ":" + str(args.port) + str(uri)
        queue.put(target)

    threads = args.threads
    for i in range(threads):
        t = ScanIP(queue, args.outfile)
        t.setDaemon(False)
        t.start()
    queue.join()

if __name__ == "__main__":
    Main()