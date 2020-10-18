#!/usr/bin/env python3

import requests
import argparse
import json
import dns.resolver
from bs4 import BeautifulSoup
from useragents import rand_user_agent

white = '\033[97m'
green = '\033[92m'
red = '\033[91m'
yellow = '\033[93m'
end = '\033[0m'

parser = argparse.ArgumentParser()
parser.add_argument("--subdomains", "-w", dest="subdomains", type=str, help="path to the file containing subdomains", required=True)
parser.add_argument("--timeout", "-t", dest="timeout", type=int, help="seconds till it will send the request", default=7)
parser.add_argument("--verbose", "-v", help="additional info", dest="verbose", action="store_true")
args = parser.parse_args()

wordlist_file_path = args.subdomains
connection_timeout = args.timeout
verbose = args.verbose

with open("subdomains_fingerprints.json", "r") as fh:
    subdomain_fingerprints = fh.read()
subdomain_fingerprints = json.loads(subdomain_fingerprints)

with open(wordlist_file_path, "r") as fh:
    for each_subdomain in fh:
        stripped_each_subdomain = each_subdomain.rstrip("\n").lstrip("https").lstrip("http").lstrip("://").rstrip("/")
        
        # only allows 3 level domains
        # (example.com is not allowed) (test.example.com is allowed)
        if len(stripped_each_subdomain.split(".")) < 3:
            print("[Invalid Subdomain] "+stripped_each_subdomain+"\n")
            continue

        try:
            # to get the cname record of the subdomain
            answers_cname = dns.resolver.query(stripped_each_subdomain, 'CNAME')
            for rdata in answers_cname:
                cname = str(rdata.target).lower().rstrip(".")
        except:
            try:
                # to get the a record of the subdomain
                answers_a = dns.resolver.query(stripped_each_subdomain, 'A')
                cname = str(answers_a[0])
            except:
                print("%s[Not Vulnerable]%s " % (red, end)+stripped_each_subdomain)
                if verbose:
                    print("%s[CNAME]%s " % (yellow, end)+cname+"\n")
                continue

        try:
            # to iterate over each service provider/engine
            for each_engine in subdomain_fingerprints:
                # to iterate over each cname of the engine
                for each_cname in each_engine["cname"]:
                    if each_cname in cname:
                        if verbose:
                            print("%s[CNAME MATCHED]%s " % (green, end)+stripped_each_subdomain)
                        if "http" not in each_subdomain or "https" not in each_subdomain:
                            each_subdomain = "http://"+stripped_each_subdomain
                        headers = {"User-Agent": rand_user_agent()}

                        try:
                            req_cname = requests.get("http://"+cname, headers=headers, timeout=connection_timeout)
                        except:
                            pass

                        try:
                            req_subdomain = requests.get(each_subdomain, headers=headers, timeout=connection_timeout)
                        except:
                            pass

                        # if statement to check if the fingerprint matches with request's response body
                        for each_fingerprint in each_engine["fingerprint"]:
                            if each_fingerprint.lower() in req_subdomain.text.lower() or each_fingerprint.lower() in BeautifulSoup(req_subdomain.text, "html.parser").text.lower() or each_fingerprint.lower() in req_cname.text.lower() or each_fingerprint.lower() in BeautifulSoup(req_cname.text, "html.parser").text.lower():
                                print("%s[VULNERABLE]%s " % (green, end)+stripped_each_subdomain+" on "+each_engine["service"]+" %s[VULNERABLE]%s " % (red, end))
                                if verbose:
                                    print("%s[CNAME]%s " % (yellow, end)+cname+"\n")
                                raise Exception()
        except:
            continue

        print("%s[NOT VULNERABLE]%s " % (red, end)+stripped_each_subdomain)
        if verbose:
            print("%s[CNAME]%s " % (yellow, end)+cname+"\n")