#!/usr/bin python

import argparse
import os
import sys

DEFAULT_DATA_DIR = '../dynamic_analysis/data'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--data_dir", help="directory where data is",
                        default=DEFAULT_DATA_DIR)
    parser.add_argument('-f', '--frequency',
                        help='analyze dns frequency', action='store_true')
    parser.add_argument('-h', '--heatmap',
                        help='generate dns use heatmap', action='store_true')
    args = parser.parse_args()
    if args.frequency:
        analyze_frequency(args.data_dir)


def analyze_frequency(data_dir):
    domains = {}
    total_count = 0
    for root, dirs, files in os.walk(data_dir):
        for f in files:
            if f in 'domains.txt':
                with open(os.path.join(root, f)) as domain_file:
                    lines = domain_file.readlines()
                    lines = [x.strip() for x in lines]
                    for domain in lines:
                        update_dic_count(domains, domain)
                total_count += 1

    sorted_domains = sorted(domains.items(), key=lambda x: x[1], reverse=True)
    for d in sorted_domains:
        frequency = (100.0 * d[1]) / total_count
        print ('%s - %f - %d' % (d[0].ljust(40), frequency, d[1]))
    print ('analyzed %d apks' % (total_count))


# updates a dictionary storing a count, creating the key if it was
# missing, and adding  input count (or 1 if left blank) to the value
def update_dic_count(dic, key, count=1):
    if key not in dic.keys():
        dic[key] = count
    else:
        dic[key] += count


if __name__ == '__main__':
    main()
