#!/usr/bin/env python3

import os
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
parser.add_argument("--output", "-o", dest="output", type=str, help="name of file in which you want to write the output")
parser.add_argument("--verbose", "-v", help="additional info", dest="verbose", action="store_true")
args = parser.parse_args()

wordlist_file_path = args.subdomains
output_file = args.output
connection_timeout = args.timeout
verbose = args.verbose

with open((os.path.abspath(os.path.dirname(__file__))+"/subdomains_fingerprints.json"), "r") as fh:
    subdomain_fingerprints = fh.read()
subdomain_fingerprints = json.loads(subdomain_fingerprints)

if output_file:
    output_file_fh = open(output_file, "w")
    vul_domains_fh = open(str(output_file)+"_vuln", "w")

# read and save subdomains in a list
wordlist_file_fh = open(wordlist_file_path, "r")
subdomains_list = wordlist_file_fh.read().split("\n")
wordlist_file_fh.close()

for each_subdomain in subdomains_list:
    stripped_each_subdomain = each_subdomain.rstrip("\n").replace("https://", "").replace("http://", "").rstrip("/")

    # skip blank records
    if stripped_each_subdomain == "":
        continue

    # only allows 3 level domains
    # (example.com is not allowed) (test.example.com is allowed)
    if len(stripped_each_subdomain.split(".")) < 3:
        ns_records = dns.resolver.query(stripped_each_subdomain, 'NS')

        for each_ns_record in ns_records:
            each_ns_record = str(each_ns_record).rstrip(".")
            # to check if this ns_record resolves to an IP address or not
            try:
                a_record_each_ns_record = dns.resolver.query(each_ns_record, 'A')
            except:
                # error mean this subdomain/domain doesn't exist
                print("%s[VULNERABLE NS RECORD DOMAIN ERROR]%s " % (green, end)+stripped_each_subdomain+" for NS record domain "+each_ns_record+"\n")
                if output_file:
                    output_file_fh.write("[VULNERABLE NS RECORD DOMAIN ERROR] "+stripped_each_subdomain+" for NS record domain "+each_ns_record+"\n")
                    vul_domains_fh.write(stripped_each_subdomain+" for NS record domain "+each_ns_record+"\n")
                # continue cause this ns record doesn't resolve to an IP address
                continue

            # to check the domain using each_ns_record, if that ns record has the record of this domain
            try:
                ns_custom_resolver = dns.resolver.Resolver()
                ns_custom_resolver.nameservers = [str(a_record_each_ns_record[0])]
                a_record_from_ns_record_ip = ns_custom_resolver.query(stripped_each_subdomain, 'A')
            except:
                # error mean this each_ns_record doesn't contain record for this stripped_each_subdomain/domain. vulnerable
                print("%s[VULNERABLE NS RECORDS]%s " % (green, end)+stripped_each_subdomain+" for NS record "+each_ns_record+"\n")
                if output_file:
                    output_file_fh.write("[VULNERABLE NS RECORDS] "+stripped_each_subdomain+" for NS record "+each_ns_record+"\n")
                    vul_domains_fh.write(stripped_each_subdomain+" for NS record "+each_ns_record+"\n")

    try:
        # to get the cname record of the subdomain
        cname = "null"
        answers_cname = dns.resolver.query(stripped_each_subdomain, 'CNAME')
        for rdata in answers_cname:
            cname = str(rdata.target).lower().rstrip(".")
    except:
        try:
            # to get the a record of the subdomain
            answers_a = dns.resolver.query(stripped_each_subdomain, 'A')
            cname = str(answers_a[0])
        except:
            if output_file:
                output_file_fh.write("[Not Vulnerable] "+stripped_each_subdomain)
            print("%s[Not Vulnerable]%s " % (red, end)+stripped_each_subdomain)
            if verbose:
                if output_file:
                    output_file_fh.write("[CNAME] "+cname+"\n")
                print("%s[CNAME]%s " % (yellow, end)+cname+"\n")
            continue

    # to iterate over each service provider/engine
    for each_engine in subdomain_fingerprints:
        # to iterate over each cname of the engine
        for each_cname in each_engine["cname"]:
            if each_cname in cname:
                if verbose:
                    if output_file:
                        output_file_fh.write("[CNAME MATCHED] "+stripped_each_subdomain)
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
                    try:
                        if each_fingerprint.lower() in req_cname.text.lower() or each_fingerprint.lower() in BeautifulSoup(req_cname.text, "html.parser").text.lower():
                            if output_file:
                                output_file_fh.write("[VULNERABLE] "+stripped_each_subdomain+" on "+each_engine["service"]+"\n")
                                vul_domains_fh.write(stripped_each_subdomain+" on "+each_engine["service"]+"\n")
                            print("%s[VULNERABLE]%s " % (green, end)+stripped_each_subdomain+" on "+each_engine["service"])
                            if verbose:
                                if output_file:
                                    output_file_fh.write("[CNAME] "+cname+"\n")
                                print("%s[CNAME]%s " % (yellow, end)+cname+"\n")
                            break
                    except:
                        pass
                    try:
                        if each_fingerprint.lower() in req_subdomain.text.lower() or each_fingerprint.lower() in BeautifulSoup(req_subdomain.text, "html.parser").text.lower():
                            if output_file:
                                output_file_fh.write("[VULNERABLE] "+stripped_each_subdomain+" on "+each_engine["service"]+"\n")
                                vul_domains_fh.write(stripped_each_subdomain+" on "+each_engine["service"]+"\n")
                            print("%s[VULNERABLE]%s " % (green, end)+stripped_each_subdomain+" on "+each_engine["service"])
                            if verbose:
                                if output_file:
                                    output_file_fh.write("[CNAME] "+cname+"\n")
                                print("%s[CNAME]%s " % (yellow, end)+cname+"\n")
                            break
                    except:
                        pass

    if output_file:
        output_file_fh.write("[NOT VULNERABLE] "+stripped_each_subdomain+"\n")
    print("%s[NOT VULNERABLE]%s " % (red, end)+stripped_each_subdomain)
    if verbose:
        if output_file:
            output_file_fh.write("[CNAME] "+cname+"\n")
        print("%s[CNAME]%s " % (yellow, end)+cname+"\n")

if output_file:
    output_file_fh.close()
    vul_domains_fh.close()
