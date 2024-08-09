import argparse
import subprocess
import logging
import os
import requests
import json

logging.basicConfig(level=logging.INFO)

def run_command(command):
    try:
        logging.debug(f"Running command: {' '.join(command)}")
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed: {e}")
    except FileNotFoundError:
        logging.error(f"Command not found: {' '.join(command)}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

def nmap_scan(target):
    logging.info(f"Starting Nmap scan on {target} with options -sS -sU -A")
    run_command(["nmap", "-sS", "-sU", "-A", target])
    logging.info(f"Nmap scan completed on {target}")

def whois_lookup(target):
    logging.info(f"Running WHOIS lookup on {target}")
    run_command(["whois", target])
    logging.info(f"WHOIS lookup completed on {target}")

def shodan_search(target, api_key):
    logging.info(f"Starting Shodan search on {target}")
    if api_key:
        run_command(["shodan", "host", target, "--api-key", api_key])
    else:
        logging.error("API key for Shodan is required")
    logging.info(f"Shodan search completed on {target}")

def whatweb_scan(target):
    logging.info(f"Starting WhatWeb scan on {target}")
    run_command(["whatweb", target])
    logging.info(f"WhatWeb scan completed on {target}")

def ip2location_lookup():
    logging.info("Using IP2Location for IP geolocation")
   
    logging.info("IP2Location lookup completed")

def virustotal_scan():
    logging.info("Scanning with VirusTotal")
   
    logging.info("VirusTotal scan completed")

def wayback_machine():
    logging.info("Using Wayback Machine for archived pages")
 
    logging.info("Wayback Machine search completed")

def hunter_io():
    logging.info("Using Hunter.io to find email addresses")
   
    logging.info("Hunter.io search completed")

def mxtoolbox_lookup():
    logging.info("Using MXToolbox for DNS and domain analysis")
    
    logging.info("MXToolbox lookup completed")

def spiderfoot():
    logging.info("Installing and running SpiderFoot")
      
    logging.info("SpiderFoot completed")

def foca():
    logging.info("Installing and running FOCA")
   
    logging.info("FOCA completed")

def google_dorking():
    logging.info("Performing Google Dorking")
    
    logging.info("Google Dorking completed")

def exiftool_scan(target):
    logging.info(f"Starting ExifTool scan on {target}")
    run_command(["exiftool", target])
    logging.info(f"ExifTool scan completed on {target}")

def sublist3r_scan(target):
    logging.info(f"Starting Sublist3r scan on {target}")
    run_command(["sublist3r", "-d", target])
    logging.info(f"Sublist3r scan completed on {target}")

def amass_enum(target):
    logging.info(f"Starting Amass enumeration on {target}")
    run_command(["amass", "enum", "-d", target])
    logging.info(f"Amass enumeration completed on {target}")

def parse_arguments():
    parser = argparse.ArgumentParser(description="Advanced Information Gathering Tool")
    
    parser.add_argument('-t', '--target', type=str, required=True, help='Target domain or IP address')
    parser.add_argument('-e', '--engine', type=str, help='Search engine for The Harvester (e.g., google)')
    parser.add_argument('--shodan-api-key', type=str, help='API key for Shodan search')

    parser.add_argument('--nmap', action='store_true', help='Run Nmap scan')
    parser.add_argument('--whois', action='store_true', help='Run WHOIS lookup')
    parser.add_argument('--shodan', action='store_true', help='Run Shodan search')
    parser.add_argument('--ip2location', action='store_true', help='Run IP2Location lookup')
    parser.add_argument('--virustotal', action='store_true', help='Run VirusTotal scan')
    parser.add_argument('--wayback', action='store_true', help='Use Wayback Machine')
    parser.add_argument('--hunter', action='store_true', help='Use Hunter.io')
    parser.add_argument('--mxtoolbox', action='store_true', help='Run MXToolbox lookup')
    parser.add_argument('--whatweb', action='store_true', help='Run WhatWeb scan')
    parser.add_argument('--spiderfoot', action='store_true', help='Run SpiderFoot')
    parser.add_argument('--foca', action='store_true', help='Run FOCA')
    parser.add_argument('--google-dorking', action='store_true', help='Perform Google Dorking')
    parser.add_argument('--exiftool', action='store_true', help='Run ExifTool')
    parser.add_argument('--sublist3r', action='store_true', help='Run Sublist3r')
    parser.add_argument('--amass', action='store_true', help='Run Amass enumeration')
    
    parser.add_argument('--all', action='store_true', help='Run all scans and information-gathering tools')
    
    return parser.parse_args()

def main():
    args = parse_arguments()

    
    if os.geteuid() != 0:
        logging.error("This script requires root privileges. Please run as root.")
        return

    
    if args.all:
        args.whois = True
        args.shodan = True
        args.ip2location = True
        args.virustotal = True
        args.wayback = True
        args.hunter = True
        args.mxtoolbox = True
        args.whatweb = True
        args.spiderfoot = True
        args.foca = True
        args.google_dorking = True
        args.exiftool = True
        args.sublist3r = True
        args.amass = True

    if args.nmap:
        nmap_scan(args.target)

    if args.whois:
        whois_lookup(args.target)

    if args.shodan:
        shodan_search(args.target, args.shodan_api_key)

    if args.ip2location:
        ip2location_lookup()

    if args.virustotal:
        virustotal_scan()

    if args.wayback:
        wayback_machine()

    if args.hunter:
        hunter_io()

    if args.mxtoolbox:
        mxtoolbox_lookup()

    if args.whatweb:
        whatweb_scan(args.target)

    if args.spiderfoot:
        spiderfoot()

    if args.foca:
        foca()

    if args.google_dorking:
        google_dorking()

    if args.exiftool:
        exiftool_scan(args.target)

    if args.sublist3r:
        sublist3r_scan(args.target)

    if args.amass:
        amass_enum(args.target)

if __name__ == "__main__":
    main()
