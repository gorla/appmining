#!/usr/bin python

import json
import os
import time
import sys
from virus_total_apis import PublicApi as VirusTotalPublicApi

# --> limited query API key
API_KEY = "f1c8d2cd8fd421b669df85d7ab727f74e58fcb6f1ec93021fdeea6b88d9e5c3e"

SCAN_RESULT_DIR = 'vt_scan'


def analyze_domain(domain):

    if domain in os.listdir(SCAN_RESULT_DIR):
        return

    print(domain)

    vt = VirusTotalPublicApi(API_KEY)

    domain_response = vt.get_domain_report(domain)

    if 'results' not in domain_response.keys():
        print('  - ERROR results not in domain_response keys')
        return True

    if domain_response['results']['verbose_msg'] == 'Domain not found':
        print('  - ERROR Domain not found')
        return True

    url_response = vt.get_url_report(domain)

    if 'results' not in url_response.keys():
        print('  - ERROR results not in url_response keys')
        return True


    if 'verbose_msg' in url_response['results'].keys() and url_response['results']['verbose_msg'] == 'Resource does not exist in the dataset': 
        vt.scan_url(domain)
        print('  - resource does not exist: asking scan')
        return False

        
    results = domain_response['results']

    if 'Websense ThreatSeeker category' in results.keys():
        url_response['Websense ThreatSeeker category'] = results['Websense ThreatSeeker category']

    if 'categories' in results.keys():
        url_response['categories'] = results['categories']

    if 'TrendMicro category' in results.keys():
        url_response['TrendMicro category'] = results['TrendMicro category']

    with open(os.path.join(SCAN_RESULT_DIR, domain), 'w') as data_file:
        data_file.write(json.dumps(url_response))

    return True


def main():
    # check args
    if (len(sys.argv) < 2):
        print("[error] - usage: python script.py domains_file")
        exit(1)

    if not os.path.exists(SCAN_RESULT_DIR):
        os.makedirs(SCAN_RESULT_DIR)

    requested_scan = []
    domains_file = sys.argv[1]
    with open(domains_file) as d_file:
        domains = d_file.read().splitlines()
    for dom in domains:
        if dom == '-':
            continue
        if dom not in os.listdir(SCAN_RESULT_DIR):
            found_data = analyze_domain(dom)
            if not found_data:
                requested_scan.append(dom)
                time.sleep(15)
            time.sleep(30)

    print("*** starting processing %d scan request ***" % (len(requested_scan)))
    for dom in requested_scan:
        analyze_domain(dom)
        time.sleep(30)
    

def generate_csv():
    domains = []
    for dom in os.listdir(SCAN_RESULT_DIR):
        
        with open(os.path.join(SCAN_RESULT_DIR, dom)) as data_file:
            data = json.load(data_file)
        if 'positives' not in data['results'].keys():
            print(data['results'])
            continue

        is_malicious = int(data['results']['positives']) > 2

        if 'Websense ThreatSeeker category' not in data.keys():
            category = 'unknown'
        else:
            category = data['Websense ThreatSeeker category']
        domains.append((dom,
                        category,
                        str(is_malicious)))
#    print domains
        with open('domain_vt.txt', 'w') as domain_file:
            for d in domains:
                domain_file.write(','.join(d) + '\r\n')
    
    return


if __name__ == "__main__":
    main()
    generate_csv()
#    analyze_domain('wwiw.sonymobile.com')

