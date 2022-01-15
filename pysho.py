#!/usr/bin/env python3

import os
import shodan
import sys
import argparse
from termcolor import colored
from time import sleep
# from pathlib import Path

def artistic_view():

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
    '''
    disclaimer = colored("              [!] Disclaimer [!]", "yellow")

    advice = colored('''
[X] The author is not responsible how this tool is used !
[X] You agree to take full responsibility for your actions !
[X] This tool is to be used for educational purposes only !
[X] Pentesting a service without written permissions is ILLEGAL !
''', "red")

    print(colored(art, "blue"))
    print(disclaimer)
    print(advice)

#initiate API key check
try:
    init_key = f"{os.getcwd()}/API_KEY"
    if not os.path.exists(init_key):
        # if os.path.isfile(init_key) and os.stat(init_key).st_size < 2:
        print(colored("[!] 'API_KEY' doesn't exist", "yellow"))
        
        k = input("[*] Enter your Shodan.io API Key: ")
        while len(k) == 0 or len(k) < 32:
            k = input("[*] Enter your Shodan.io API Key: ")
        
        with open(f"{os.getcwd()}/API_KEY", "w") as key_file:
            key_file.write(str(k))
            key_file.close()
        
        print(colored("[+] API key saved !", "green"))
        sleep(0.5)
    
    else:
        print(colored("\r\n[+] API key exists in file 'API_KEY', Continuing...", "green"))
        # sleep(1)
        with open(f"{os.getcwd()}/API_KEY", "r") as key_file:
            k = key_file.readline().rstrip('\n')

except KeyboardInterrupt:
    print(colored("\r\n[!] KeyboardInterrupt: Exitting !", "yellow"))
    sys.exit(0)

#Clear screen after API_KEY check
os.system('cls' if os.name == 'nt' else 'clear')

#Initiate connection to Shodan.io
connect = shodan.Shodan(k)

#Check api key info
def key_info():
    try:
        key = connect.info()
        print(f"[*] Scan Credits: {colored(key['scan_credits'], 'green')}")
        print(f"[*] Query Credits: {colored(key['query_credits'], 'green')}")
        print(f"[*] Monitored IPs: {colored(key['monitored_ips'], 'green')}")
        print(f"[*] Plan: {colored(key['plan'], 'green')}")
        print(f"[*] HTTPS ?: {colored(key['https'], 'white')}")
        print(f"[*] Unlocked ?: {colored(key['unlocked'], 'white')}")
        print(f"[*] Telnet ?: {colored(key['telnet'], 'white')}")
        print(f"[*] Unlocked Left: {colored(key['unlocked_left'], 'green')}")
    except shodan.APIError as e:
        print(colored(f'[-] API Error: {e}', "red"))

#Lookup by IP
def host(i):
    try:
        try:
            print("[+] Looking up {}\r\n".format(colored(str(i), "cyan")))
            
            #Lookup the host
            findings = connect.host(str(i))
            
            #Print general info
            print(f"[#] Organization: {colored(findings['org'], 'green')}")
            print(f"[#] Operating System: {colored(findings['os'], 'green')}")
            for result in findings['data']:
                print(f"[#] Port: {colored(result['port'], 'green')}")
                print("[>>] Banner:")
                print(f"\r\n{colored(result['data'], 'magenta')}")
                print(colored("-+"*50, "white"))
        
        except shodan.APIError as e:
            print(colored(f'[-] API Error: {e}', 'red'))
            sleep(0.5)
    
    except KeyboardInterrupt:
        print(colored("\r\n[!] KeyboardInterrupt: Exitting !", "yellow"))
        sys.exit(0)

#Lookup by service (smb, apache, nginx ,etc)
def ip_lookup(s):
    try:
        try:
            print(f"[+] Searching for: {colored(s, 'cyan')}\r\n")
            
            # Search Shodan
            findings = connect.search(str(s))
            
            # Show the results, if None raise exception
            print(f'Results found: {colored(findings["total"], "red", attrs=["bold"])}\r\n')
            sleep(1.5) #Leave a moment to check total number of results found
            
            for result in findings['matches']:
                print(f'[#] IP: {colored(result["ip_str"], "green")}')
                print(f'[#] Port: {colored(result["port"], "green")}')
                print(f'[#] Organization: {colored(result["org"], "green")}')
                print(f'[#] Location: {colored(result["location"], "green")}')
                print(f'[#] Layer: {colored(result["transport"], "green")}')
                print(f'[#] Domains: {colored(result["domains"], "green")}')
                print(f'[#] Hostnames: {colored(result["hostnames"], "green")}')
                print("[>>] Banner: ")
                print(colored(result['data'], "magenta"))
                print(colored('-+'*50, "white") + "\r\n")
        
        except shodan.APIError as e:
            print(colored(f'[-] API Error: {e}', "red"))
            sleep(0.5)

    except KeyboardInterrupt:
        print(colored("\r\n[!] KeyboardInterrupt: Exitting !", "yellow"))
        sys.exit(0)

#Initialize "pysho" :)
if __name__ == "__main__":

    #Print the beautiful art above :)
    # print(colored(art, "blue"))
    artistic_view()
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
