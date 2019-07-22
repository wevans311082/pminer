pminer.py
PCAP Non-RFC 1918 address miner - that automatically checks abuseipdb

Why did I create this simple tool.  I couldn't find a quick and simple pcap parser that would extract only public net address and send them to abuseipdb.  A simple and basic check.  

The tool checks both src and dst IP from a TCP packet capture.  

You provide this file with a pcap and it will parse it using dpkt and extract all external IP's and then check them against the abuseipdb and display the results.

you will need a free 1000 request AbuseIPDB api key from their website :- https://www.abuseipdb.com/

When you have an API key - Update it in the pminer.py file

usage: pminer.py pcapfile.pcap



