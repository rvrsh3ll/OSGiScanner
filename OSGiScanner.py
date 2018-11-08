import urllib2
import ssl
import ipcalc
import argparse
import logging
import threading
import httplib


def scan_ip(ip, port, secure):
    
    # Bypass errors for bad SSL certs
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # URI to the console. Default location.
    uri = '/system/console'
    if port == 443:
        protocol = "s"
    else:
        if secure:
            protocol = "s"
        else:
            protocol = ""
    target = "http" + str(protocol) + "://" + str(ip) + ":" + str(port) + str(uri)
    print "[*] Starting scanning against " + target
    try:
        req = urllib2.Request(target)
        req.addheaders = [('User-Agent', 'Mozilla/5.0 (Windows NT 6.3; Win64; x64; Trident/7.0; rv:11.0) like Geckos')]
        handle = urllib2.urlopen(req, context=ctx, timeout=4)
        return true
    except (IOError, httplib.BadStatusLine) as e:
        if hasattr(e, 'code'):
            if e.code != 401:
                pass
            else:
                if ("OSGi" in e.headers['www-authenticate']):
                    print "[*] Found OSGi Console at " + target
                    logger.info("[*] Found OSGi Console at " + target)
        else:
            pass
        
if __name__ == "__main__":
    # Script argument parsing
    parser = argparse.ArgumentParser(description='A script to identify OSGi Consoles')
    parser.add_argument('--cidr', type=str, metavar='CIDR', nargs=1, help='CIDR notation i.e 192.168.1.10/24', required=True)
    parser.add_argument('--port', type=int, help='Port number', required=True)
    parser.add_argument('--ssl', action='store_true', default=False, help='Enable SSL', required=False)
    parser.add_argument('--outfile', action='store', default='osgi_scanner.log', help='Log results to this file')
    args = parser.parse_args()

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

    threads = [threading.Thread(target=scan_ip, args=(ip,args.port,args.ssl,)) for ip in ipcalc.Network(args.cidr[0])]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()