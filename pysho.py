#!/usr/bin/env python

import os
import shodan
import sys
import argparse
from termcolor import colored
from time import sleep
from pathlib import Path

art = '''
@@@@@@@   @@@ @@@   @@@@@@   @@@  @@@   @@@@@@
@@@@@@@@  @@@ @@@  @@@@@@@   @@@  @@@  @@@@@@@@
@@!  @@@  @@! !@@  !@@       @@!  @@@  @@!  @@@
!@!  @!@  !@! @!!  !@!       !@!  @!@  !@!  @!@
@!@@!@!    !@!@!   !!@@!!    @!@!@!@!  @!@  !@!
!!@!!!      @!!!    !!@!!!   !!!@!!!!  !@!  !!!
!!:         !!:         !:!  !!:  !!!  !!:  !!!
:!:         :!:        !:!   :!:  !:!  :!:  !:!
 ::          ::    :::: ::   ::   :::  ::::: ::
 :           :     :: : :     :   : :   : :  :

                v0.1   @Kr0ff

              [!] Disclaimer [!]

[X] The author is not responsible how this tool is used !
[X] You agree to take full responsibility for your actions !
[X] This tool is to be used for educational purposes only !
[X] Pentesting a service without written permissions is ILLEGAL !
'''
print(colored(art, "blue"))

#initiate API key check
try:
    init_key = Path("./API_KEY")
    if init_key.is_file() and os.stat(init_key).st_size < 2:
        with open("API_KEY", "w") as key_file:
            print(colored("[!] 'API_KEY' file is empty...", "yellow"))
            sleep(1)
            k = input("[*] Enter your Shodan.io API Key: ")
            while len(k) == 0 or len(k) < 32:
                k = input("[*] Enter your Shodan.io API Key: ")
            key_file.write(str(k))
            print(colored("[+] API key saved !", "green"))
            key_file.close()
    else:
        print(colored("\r\n[+] API key exists in file 'API_KEY', Continuing...", "green"))
        sleep(1)
        with open("./API_KEY") as key_file:
            k = key_file.readline().rstrip('\n')
except KeyboardInterrupt:
    print(colored("[!] KeyboardInterrupt: Exitting !", "yellow"))
    sys.exit(0)

#Clear screen after API_KEY check
os.system('cls' if os.name == 'nt' else 'clear')

#Initiate connection to Shodan.io
connect = shodan.Shodan(k)

#Check api key info
def key_info():
    try:
        key = connect.info()
        print("[*] Scan Credits: %s" % colored(key['scan_credits'], "green"))
        print("[*] Query Credits: %s" % colored(key['query_credits'], "green"))
        print("[*] Monitored IPs: %s" % colored(key['monitored_ips'], "green"))
        print("[*] Plan: %s" % colored(key['plan'], "green"))
        print("[*] HTTPS ?: %s" % colored(key['https'], "white"))
        print("[*] Unlocked ?: %s" % colored(key['unlocked'], "white"))
        print("[*] Telnet ?: %s" % colored(key['telnet'], "white"))
        print("[*] Unlocked Left: %s" % colored(key['unlocked_left'], "green"))
    except shodan.APIError as e:
        print(colored('[-] API Error: {}'.format(e), "red"))

#Lookup by IP
def host(i):
    try:
        try:
            print("[+] Looking up {}\r\n".format(colored(str(i), "cyan")))
            #Lookup the host
            findings = connect.host(str(i))
            #Print general info
            print("[#] Organization: {}".format(colored(findings['org'], "green")))
            print("[#] Operating System: {}".format(colored(findings['os'], "green")))
            for result in findings['data']:
                print("[#] Port: {}".format(colored(result['port'], "green")))
                print("[>>] Banner:")
                print("\r\n{}".format(colored(result['data'], "magenta")))
                print(colored("-+"*50, "white"))
        except shodan.APIError as e:
            print(colored('[-] API Error: {}'.format(e), 'red'))
            sleep(0.5)
    except KeyboardInterrupt:
        print(colored("\r\n[!] KeyboardInterrupt: Exitting !", "yellow"))
        sys.exit(0)

#Lookup by service (smb, apache, nginx ,etc)
def ip_lookup(s):
    try:
        try:
            print("[+] Searching for: {}\r\n".format(colored(s, "cyan")))
            # Search Shodan
            findings = connect.search(str(s))
            # Show the results, if None raise exception
            print('Results found: {}\r\n'.format(colored(findings['total'], "red", attrs=["bold"])))
            sleep(1.5) #Leave a min to check total number of results found
            for result in findings['matches']:
                print('[#] IP: {}'.format(colored(result['ip_str'], "green")))
                print('[#] Port: {}'.format(colored(result['port'], "green")))
                print('[#] Organization: {}'.format(colored(result['org'], "green")))
                print('[#] Location: {}'.format(colored(result['location'], "green")))
                print('[#] Layer: {}'.format(colored(result['transport'], "green")))
                print('[#] Domains: {}'.format(colored(result['domains'], "green")))
                print('[#] Hostnames: {}'.format(colored(result['hostnames'], "green")))
                print("[>>] Banner: ")
                print('{}'.format(colored(result['data'], "magenta")))
                print(colored('-+'*50, "white"))
                print("")
        except shodan.APIError as e:
            print(colored('[-] API Error: {}'.format(e), "red"))
            sleep(0.5)
    except KeyboardInterrupt:
        print(colored("\r\n[!] KeyboardInterrupt: Exitting !", "yellow"))
        sys.exit(0)

#Initialize "pysho" :)
if __name__ == "__main__":

    #Print the beautiful art above :)
    print(colored(art, "blue"))
    #Setup the argument parser
    parser = argparse.ArgumentParser(description='Search Shodan.io using the Shodan API')
    parser.add_argument("-i", "--ip_address", help="Host to search by IP", type=str)
    parser.add_argument("-s", "--search", help="Service to search (apache, nginx, smb, etc...)", type=str)
    parser.add_argument("--info", help="Get information about your API key", action="store_true")
    args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])

    s = args.search
    i = args.ip_address
    keyinfo = args.info
    ###Check which arg is used
    if s:
        ip_lookup(s)
    if i:
        host(i)
    if keyinfo:
        key_info()
