import json
import re
import sys
import argparse

types = {'V': "void", 'Z': "boolean", 'I': "int", 'F': "float", 'J': "long", 'D': "double", 'B': "byte",
         'C': "char", 'S': "short"}
param_regex = re.compile('(?P<obj>\[*L[^;]+?;)|(?P<prim>\[*[ZIFJBDCS])')


def split_param(arg):
    arg = arg.replace("/", ".")
    matches = re.findall(param_regex, arg)
    return [convert_type(x or y) for x, y in matches]


def convert_type(arg):
    array_count = arg.count('[')
    arg = arg.strip('[')
    if arg in types.keys():
        res = types[arg]
    else:
        res = arg.strip("L;").replace("/", ".")
    return res + '[]' * array_count


def parse_api(api):
    # Landroid/provider/ContactsContract$StatusUpdates;-CONTENT_URI-Landroid/net/Uri;
    signature = api.split('-')
    class_name = convert_type(signature[0])
    method_name = signature[1]
    subsign = signature[2]
    is_method = subsign.startswith('(')
    if not is_method:
        print signature
        return ''
    arg_list = re.sub("\(([^)]*)\).*", "\\1", subsign)
    ret_type = convert_type(re.sub("\([^)]*\)(.*)", "\\1", subsign))
    params = split_param(arg_list.replace(' ', ''))
    return '<' + class_name + ': ' + ret_type + ' ' + method_name + '(' + ','.join(params) + ')>'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Translate androguard permission mapping into jimple format. Input file MUST contain a valid json dictionary')
    parser.add_argument("input")
    parser.add_argument("output")
    args = parser.parse_args()
    perm_file = args.input
    translated_perm_file = args.output
    perm_mapping = dict()
    with open(perm_file, "r") as f:
        mapping = json.load(f)
        for api, perm_list in mapping.items():
            jimple_api = parse_api(api)
            if jimple_api != '':
                perm_mapping[jimple_api] = perm_list
    with open(translated_perm_file, "w") as tf:
        json.dump(perm_mapping, tf, indent=1)
