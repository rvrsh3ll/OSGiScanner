# OSGiScanner

OSGiScanner is a simple Python 2.7 tool written to aid Penetration Testers in finding OSGi consoles.

OSGi consoles commonly have the default username and password combination of admin:admin.

Once a Tester has gained access to an OSGi console, they may be able to execute groovy script via the script console or deploy malicous bundle packages.

I've previously documented both attack types:
[Leveraging Adobe Live Cycle](https://medium.com/rvrsh3ll/leveraging-adobe-livecycle-202ce6772461)
[Shelling Apache Felix With Java Bundles](https://posts.specterops.io/shelling-apache-felix-with-java-bundles-2450d3a099a)

To find OSGi consoles, we simply search for the "/system/console" directory. The web request typically requires Basic auth and we can use the fingerprint 'WWW-Authenticate: Basic realm="OSGi Management Console"' to detect such a console.

On [Shodan](https://shodan.io), you can may find these consoles inside your target range by using the basic auth fingerprint as a search term.
![alt text](https://raw.githubusercontent.com/rvrsh3ll/OSGiScanner/master/ShodanResult.png?token=AF5nU1FpUEEdItiwvHASW0ZGL6ZSKbgsks5b7eYpwA%3D%3D)

Next, execute OSGi scanner against that host or range of hosts to discover more potential targets.

#### Example usage
python OSGiScanner.py --cidr 10.10.1.0/24 --port 80 --oufile myscan.log
##### OR an example using SSL
python OSGiScanner.py --cidr 10.10.1.0/24 --port 443
##### OR an example using SSL on different port
python OSGiScanner.py --cidr 10.10.1.0/24 --port 443 --ssl

