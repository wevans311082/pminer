import dpkt
import socket
import ipaddress
import requests
import json
import sys
import os.path
from colorama import init
from termcolor import colored

abuseip_apikey = '255afc21aa4c12ddf737d7840f135b40ed1ab67e168fb803e41c4b6d63a3fb28af474582619fec25'


def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def is_ip_on_lan(ip:str) -> bool:
    return ipaddress.IPv4Address(ip).is_private


def check_ip(ip):
    try:
        url = 'https://api.abuseipdb.com/api/v2/check'

        querystring = {
            'ipAddress': ip,
            'maxAgeInDays': '90'
        }

        headers = {
            'Accept': 'application/json',
            'Key': abuseip_apikey
        }
        # print(querystring)
        # print(headers)
        response = requests.request(method='GET', url=url, headers=headers, params=querystring)

        # Formatted output
        decodedResponse = json.loads(response.text)
        print(decodedResponse)
        return decodedResponse

    except:
        print(colored("Unable to Check IP",'red'))
        return "Unable to Check IP"


def main():
    ip_list = []

    if sys.argv[1] == "-v":
        display_usage()

    if sys.argv[1] == "--version":
        display_usage()

    if os.path.exists(sys.argv[1]):
        pcapfile = sys.argv[1]
    else:
        print(colored("Error - PCAP file not found" + sys.argv[1]),'red')
        sys.exit(1)

    file = open(pcapfile, 'rb')
    pcap = dpkt.pcap.Reader(file)

    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data

        if not is_ip_on_lan(ip.src):
            print('ip:', inet_to_str(ip.src), "->", inet_to_str(ip.dst))
            ip_list.append(inet_to_str(ip.src))

        if not is_ip_on_lan(ip.dst):
            print('ip:', inet_to_str(ip.src), "->", inet_to_str(ip.dst))
            ip_list.append(inet_to_str(ip.dst))

    file.close()
    print(colored('External IP to check against AbuseIPDB:', 'green'))
    ip_list = set(ip_list)

    for ip in ip_list:
        print(colored(ip,'white','on_red'))
        check_ip(ip)


def display_usage():
    print(colored("Pcap Miner 0.0.1", "yellow"), colored("- Simple tool to extract non-rfc 1918 IPs from PCAP file",
                                                        'white'))
    print("requires an abuseipdb API key hint(edit pminer.py to insert API Key)")
    print(colored("usage: pminer.py pcapfile.pcap", 'red'))
    sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        display_usage()
    main()
