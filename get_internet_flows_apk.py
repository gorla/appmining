# get_internet_flows_apk.py
import os
import json
import csv

path_to_json = ""
mapping_file = ""
out_file = ""


def csv_file_to_dict():
    with open(mapping_file, 'r') as infile:
        reader = csv.reader(infile, delimiter=';')
        dictionary = {rows[0]: rows[1] for rows in reader}
        return dictionary


def to_class(loc):
    clazz = loc.split('.')[0]
    return clazz.replace('/', '.')


def get_apk(content):
    for apk in content['apks']:
        vercode = apk['vercode']
        pkg = apk['pkg']
        app_name = pkg + '_' + vercode
        for flow in apk['ss']:
            sink = '<' + flow['sink']['name'] + '>'
            if mapping[sink] == 'INTERNET':
                decl_class = to_class(flow['sink']['loc'])
                return app_name, decl_class
    return None, None


mapping = csv_file_to_dict()
lines = []
for root, dirs, files in os.walk(path_to_json):
    for f_name in files:
        with open(os.path.join(root, f_name), "r") as f:
            content = json.load(f)
            apk, clazz = get_apk(content)
            if apk is not None:
                line = apk + ';' + clazz + '\n'
                lines.append(line.encode('utf-8'))
with open(out_file, 'w') as f:
    f.writelines(lines)
