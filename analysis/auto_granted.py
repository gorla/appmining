# coding=utf-8
import argparse
import json
import operator
import os
import sys

sys.path.append("..")
import cfg

from constants import DANGEROUS_GROUPS
from constants import DANGEROUS_PERM_LIST


# lists package, version and automatically granted permission for all apps in the
# cfg.permission_app_folder (output of PermissionApp in permission_luigi.py task)
def list_auto_granted(print_stats):
    agp = {}
    pkgs = 0
    apks = 0
    ag_apks = 0

    # recursively get the list of all json files inside the permission app dir
    target_dir = os.path.join(cfg.evo_data_folder, cfg.permission_app_folder)
    files = [os.path.join(dp, f) for dp, dn, filenames in
             os.walk(target_dir) for f in filenames
             if os.path.splitext(f)[1] == '.json']
    for f in files:
        pkgs += 1
        with open(f) as data_file:
            app = json.load(data_file)
        pkg = os.path.splitext(os.path.basename(f))[0]
        for ver, info in app.items():
            apks += 1
            if 'auto_granted' in info.keys():
                ag_apks += 1
                for perm in info['auto_granted']:
                    print('%s,%s,%s' % (pkg, ver, perm))
                    if perm not in agp.keys():
                        agp[perm] = 0
                    agp[perm] += 1
    if print_stats:
        print('pkgs analyzed: %d' % pkgs)
        print('apks analyzed: %d' % apks)
        print('apks with auto granted permissions: %d' % ag_apks)
        for p, c in agp.items():
            print('%s : %d' % (p, c))


# prints the list of added apis related to granted permissions, together with
# version, permissions which the api requires and are granted, and libs where
# the api is used
def list_api_evolution(print_stats, target_dir=None):
    evo_perm_stats = {}
    api_stats = {}
    api_c = 0
    lib_c = 0
    app_c = 0

    # recursively get the list of all json files inside the api evolution dir
    if target_dir is None:
        target_dir = os.path.join(cfg.evo_data_folder,
                                  cfg.permission_api_evolution_folder)
    files = [os.path.join(dp, f) for dp, dn, filenames in
             os.walk(target_dir) for f in filenames
             if os.path.splitext(f)[1] == '.json']

    for f in files:
        # open api_evolution json file
        with open(f) as data_file:
            api_evo_app = json.load(data_file)

        # get pkg name
        pkg = os.path.splitext(os.path.basename(f))[0]

        # cycle all versions in chronological order
        for ver, api_dict in iter(sorted(api_evo_app['evo'].items(),
                                         key=lambda i: int(i[0]))):
            # cycle all version's apis
            for api, api_info in api_dict.items():

                perms = api_info['perms']
                locs = api_info['locs']
                # update statistics
                if print_stats:

                    # add 1 to api count and update count
                    # of uses in appcode or libraries
                    api_c += 1

                    app_use = 'appcode' in locs or 'appcode/' in locs
                    lib_use = any([(loc != 'appcode' and loc != 'appcode/' and
                                    loc != '_OBFUSCATED_') for loc in locs])

                    # update app and lib use
                    if app_use:
                        app_c += 1
                    if lib_use:
                        lib_c += 1

                    # update api stats
                    if api not in api_stats:
                        api_stats[api] = {'app&lib': 0, 'app': 0, 'lib': 0}
                    if app_use and lib_use:
                        api_stats[api]['app&lib'] += 1
                    elif app_use:
                        api_stats[api]['app'] += 1
                    elif lib_use:
                        api_stats[api]['lib'] += 1

                    for p in perms:
                        perm = p.rstrip('*')
                        if perm not in evo_perm_stats:
                            evo_perm_stats[perm] = {'app': 0, 'lib': 0, 'app&lib': 0}
                        if app_use and lib_use:
                            evo_perm_stats[perm]['app&lib'] += 1
                        elif app_use:
                            evo_perm_stats[perm]['app'] += 1
                        elif lib_use:
                            evo_perm_stats[perm]['lib'] += 1

    if print_stats:
        print('api analyzed: %d' % (api_c))
        print('uses in libs: %d  |  uses in appcode: %d' %
              (lib_c, app_c))

        perms = sorted(evo_perm_stats.items(), key=lambda x: x[1]['app&lib'] + x[1]['app'] + x[1]['lib'],
                       reverse=True)

        print('\nPermission API stats:')
        for p in perms:
            print('%s - %d (a&l %d, app %d, lib %d)' %
                  (p[0], p[1]['app&lib'] + p[1]['app'] + p[1]['lib'],
                   p[1]['app&lib'], p[1]['app'], p[1]['lib']))

def print_mapping():
    # get all androguard mappings files
    files = [os.path.join(dp, f) for dp, dn, filenames in os.walk('../apktool/androguard_api_perm_mappings/') for f in
             filenames if os.path.splitext(f)[1] == '.txt']

    mappings = {}
    for p in DANGEROUS_PERM_LIST:
        mappings[p] = set()
    for f in files:
        with open(f) as data_file:
            androguard_api = json.load(data_file)
        for api, perms in androguard_api.items():
            for permission in perms:
                # remove android.permission.
                perm = permission[len('android.permission.'):]
                if perm in DANGEROUS_PERM_LIST:
                    mappings[perm].add(api)
    for p, apis in mappings.items():
        with open(p + '.txt', 'w') as data_file:
            data_file.write('\r\n'.join(apis))


# gets all json files in the target folder and outputs, for each
# pkg and version, which API of an automatically granted permission are
# used in the apk
def list_auto_granted_apis(print_stats):
    autogranted_api_dir = os.path.join(cfg.evo_data_folder,
                                       cfg.permission_autogranted_api_folder)
    pkgs_c = 0
    apks_c = 0
    apis_c = 0
    for root, dirs, files in os.walk(autogranted_api_dir):
        for f in files:
            if f.endswith(".json"):
                pkgs_c += 1
                with open(os.path.join(root, f)) as data_file:
                    app = json.load(data_file)
                    pkg = os.path.basename(f).split('.json')[0]
                    for ver, apk in app.items():
                        apks_c += 1
                        print(pkg + ' ' + ver)
                        for perm, apis in apk.items():
                            print('- ' + perm)
                            for api in apis:
                                print('    ' + api)
                                apis_c += 1
    if print_stats:
        print('pkgs analyzed: %d' % pkgs_c)
        print('apks analyzed: %d' % apks_c)
        print('apis with auto granted permissions: %d' % apis_c)


# gets a flow dictionary object and creates a string to be printed
def flow_to_string(flow):
    res = '  > src: ' + flow['source']['name'] + ' | '
    res += flow['source']['loc'].encode('ascii', 'ignore') + '\n'
    res += '    sink: ' + flow['sink']['name'] + ' | '
    res += flow['sink']['loc'].encode('ascii', 'ignore') + '\n'
    return res


# gets all the json files for flowdroid_json folder and prints for each,
# pkg/ver, which flows have been found
def list_auto_granted_flows(print_stats):
    pkg_set = set()
    total_pkg_c = 0
    total_apk_c = 0
    apk_c = 0
    flow_c = 0
    total_incomplete_c = 0
    autogranted_flow_dir = os.path.join(cfg.evo_data_folder,
                                        cfg.permission_flowdroid_app_folder)
    for root, dirs, files in os.walk(autogranted_flow_dir):
        for f in files:
            if f.endswith(".json"):
                # update total package analyzed count 
                total_pkg_c += 1

                with open(os.path.join(root, f)) as data_file:
                    app = json.load(data_file)
                    for apk in app['apks']:
                        total_apk_c += 1

                        # count how many incomplete we have in total
                        if 'incomplete' in apk.keys():
                            if apk['incomplete']:
                                total_incomplete_c += 1

                        # if there are now flows found, skip the apk
                        if len(apk['ss']) == 0:
                            continue

                        # extract package and version
                        pkg = apk['pkg']
                        ver = apk['vercode']

                        # update count of apks and pkgs with flows
                        apk_c += 1
                        pkg_set.add(pkg)

                        print('' + pkg + ' ' + ver)
                        for flow_dict in apk['ss']:
                            flow_c += 1
                            print("> src: " + flow_dict['source']['name'])
                            print("       " + flow_dict['source']['loc'].encode('ascii', 'ignore'))
                            print(" sink: " + flow_dict['sink']['name'])
                            print("       " + flow_dict['sink']['loc'].encode('ascii', 'ignore'))
                        print(' ----- ')
    if print_stats:
        print('Analyzed %d pkgs with %d apks. We have %d apks with incomplete flow analysis' %
              (total_pkg_c, total_apk_c, total_incomplete_c))
        print('Found %d pkgs, with %d apks containing flows' % (apk_c, len(pkg_set)))
        print('flows found: %d' % flow_c)


# returns the permission group of input permission
def get_perm_group(perm):
    for g, pl in DANGEROUS_GROUPS.items():
        if perm in pl:
            return g


# returns the list of permissions that allow the input perm to be auto granted
def get_auto_granted_enablers(perm, info, prev_autogranted, prev_perms):
    # if the permission was automatically granted in the previous version skip
    # looking for enablers and return prev_ver
    if prev_autogranted is not None and perm in prev_autogranted:
        return ['PREVIOUS_VERSION']

    # cycle requested perms and see which are in the same group as the input
    # the permission must have been granted in the previous version
    enablers = []
    perm_group = get_perm_group(perm)
    for p in info['perms']:
        if p == perm:
            continue
        if p in DANGEROUS_GROUPS[perm_group] and p in prev_perms:
            enablers.append(p)
    return enablers


# returns the list of api invocation for the input permission, pkg and version
def get_perm_apis(perm, pkg, ver):
    # try to open the autogranted apis file
    autogranted_api_filepath = os.path.join(cfg.evo_data_folder,
                                            cfg.permission_autogranted_api_folder,
                                            pkg, pkg + '.json')
    if not os.path.isfile(autogranted_api_filepath):
        return {}
    with open(autogranted_api_filepath) as data_file:
        app = json.load(data_file)
    if (ver not in app or
            perm not in app[ver]):
        return {}
    return app[ver][perm]


# returns the api part of source. if there are brackets (< and >), the method
# returns the text inside, otherwise if any bracket is missing it returls text
# from beginning or end of input string
def get_src_api(src_name):
    start = src_name.find('<')
    if start == -1:
        start = 0
    else:
        # skip the '<' character
        start += 1

    end = src_name.find('>')
    if end == -1:
        end = len(src_name)

    return src_name[start:end]


# returns the apk flos that require the input permission
def get_perm_flows(perm, apk_flows, api_mapping):
    target_dict = {'ACCESS_COARSE_LOCATION': ['ACCESS_LOCATION'],
                   'ACCESS_FINE_LOCATION': ['ACCESS_LOCATION'],

                   }
    target = [perm]
    if perm in target_dict:
        target.extend(target_dict[perm])
    perm_flows = []
    for flow in apk_flows:
        src_name = flow['source']['name']

        # get src/sink api string (+1 on index to remove the brackets < and >
        src_api = get_src_api(src_name)
        sink_api = flow['sink']['name']

        # if we can't map neither source nor sink to an api,
        # then we are missing some mappings
        if (src_api not in api_mapping and
                sink_api not in api_mapping):
            print(flow)
            print('[ERROR] missing mapping in get_perm_flows')
            import pdb
            pdb.set_trace()
            pass

        # if source or sink api are in mappings, see if they
        # require input permission
        if src_api in api_mapping and api_mapping[src_api] in target:
            perm_flows.append(flow_to_string(flow))

        elif sink_api in api_mapping and api_mapping[sink_api] in target:
            perm_flows.append(flow_to_string(flow))

    return perm_flows


def print_combined_perm_stats(perm, perm_data):
    # variables for statistics
    enablers = {}
    app_and_lib_use = 0
    appcode_use = 0
    lib_use = 0
    obfuscated_use = 0
    missing_use = 0

    # parse all versiosn that have the permission automatically granted
    for perm_info in perm_data:
        # update enablers stats
        for e in perm_info['enablers']:
            if e not in enablers:
                enablers[e] = 0
            enablers[e] += 1
        found_lib = False
        found_appcode = False
        found_obf = False

        # check if there are apis in each of the three location categories
        for api, locs in perm_info['apis'].items():
            if 'appcode' in locs:
                found_appcode = True
            if '_OBFUSCATED_' in locs:
                found_obf = True
            for loc in locs:
                if loc != 'appcode' and loc != '_OBFUSCATED_':
                    found_lib = True
                    break

        # updated stats with found location uses
        if found_appcode and found_lib:
            app_and_lib_use += 1
        elif found_appcode:
            appcode_use += 1
        elif found_lib:
            lib_use += 1
        elif found_obf and not found_appcode and not found_lib:
            obfuscated_use += 1
        else:
            missing_use += 1

    # print statistics
    use_count = len(perm_data)
    print(perm + ' - %d apks found' % use_count)
    print('  enablers: %s' % ', '.join(['%s: %d' % (k, v) for k, v in enablers.items()]))
    print('  API stats - app&lib: %d | app: %d | lib: %d | obfuscated: %d | missing: %d (%.1f%%)' % (
        app_and_lib_use, appcode_use, lib_use, obfuscated_use, missing_use, float(100 * missing_use / use_count)))


# write the input permission statistics on an external file
def dump_perm_stats(perm, perm_data):
    output_folder = 'dump'

    # create output folder if it does not exist yet
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # write info to file
    with open(os.path.join(output_folder, perm + '.txt'), 'w') as f:
        for perm_info in perm_data:

            # write header line for package, version and enablers
            pkg_line = perm_info['pkg']
            pkg_line += ' | ' + str(perm_info['ver'])
            pkg_line += ' | granted by: ' + ', '.join(perm_info['enablers']) + '\r\n'
            f.write(pkg_line)

            # for each api, write api and corresponding use locations
            for api, locs in perm_info['apis'].items():
                f.write('  ' + api + ' | ' + ', '.join(locs) + '\r\n')

            for flow in perm_info['flows']:
                f.write(flow)


# analyzes all automatically granted permissions, and reports for each of them
# which other permission gave him the auto grant and which api invocations were
# found in the code related to it
def combined_analysis(dump, print_stats, skip_prev_ver_enabler):
    # get all files in the permission app folder
    target_dir = os.path.join(cfg.evo_data_folder,
                              cfg.permission_app_folder)
    perm_app_files = [os.path.join(dp, f) for dp, dn, filenames in
                      os.walk(target_dir) for f in filenames
                      if os.path.splitext(f)[1] == '.json']

    # open permission_mapping file and create a dictionary with
    # api and corresponding permission required
    api_mapping = {}
    with open('../flowdroid/permission_mapping.txt') as data_file:
        perm_mapping_lines = data_file.read().splitlines()
    for line in perm_mapping_lines:
        api = line.split(';')[0].lstrip('<').rstrip('>')
        perm = line.split(';')[1]
        if (perm.startswith(('*', 'NAN', '---')) or
                api.startswith('CONTENT_RESOLVER')):
            continue

        api_mapping[api] = perm

    # create permission dictionary
    perm_dict = {}

    # parse all version in the file and get all automatically granted perms.
    for f in perm_app_files:
        with open(f) as data_file:
            perm_app = json.load(data_file)
        pkg = os.path.splitext(os.path.basename(f))[0]

        # get flows from FlowdroidApp task
        flowdroid_app_fpath = os.path.join(cfg.evo_data_folder,
                                           cfg.permission_flowdroid_app_folder,
                                           pkg, pkg + '.json')

        flow_app = {}
        if os.path.isfile(flowdroid_app_fpath):
            with open(flowdroid_app_fpath) as data_file:
                # load flow  json and save flows for versions that have any
                for apk in json.load(data_file)['apks']:
                    if len(apk['ss']) > 0:
                        flow_app[apk['vercode']] = apk['ss']

        perm_app_it = iter(sorted(perm_app.items(), key=lambda i: int(i[0])))
        prev_autog = None
        prev_perms = []

        for ver, info in perm_app_it:
            # parse all auto granted permissions, if any is present
            if 'auto_granted' in info.keys():
                for perm in info['auto_granted']:
                    # create permission info dictionary
                    perm_info = {'pkg': pkg, 'ver': int(ver)}

                    # for each auto granted permission check which permission
                    # is enabling it
                    perm_info['enablers'] = get_auto_granted_enablers(perm, info,
                                                                      prev_autog,
                                                                      prev_perms)

                    # if skip previous version enablers is True, skip
                    # all permissions enabled by previous version
                    if (skip_prev_ver_enabler and
                            'PREVIOUS_VERSION' in perm_info['enablers']):
                        continue

                    # get all apis invocation of the permission
                    perm_info['apis'] = get_perm_apis(perm, pkg, ver)

                    # get all permissions flows that require the permission.
                    # if flow_app does not contain version, set to empty list
                    if ver in flow_app:
                        perm_info['flows'] = get_perm_flows(perm, flow_app[ver],
                                                            api_mapping)
                    else:
                        perm_info['flows'] = []

                    # add perm to dict if not present
                    if perm not in perm_dict:
                        perm_dict[perm] = []

                    # add perm_info to dictionary
                    perm_dict[perm].append(perm_info)
                prev_autog = info['auto_granted']
                prev_perms = info['perms']
            else:
                prev_autog = None
                prev_perms = info['perms']

    # for each permission dump the statistics
    for perm, perm_data in perm_dict.items():
        # if print stats is enabled, compute perm statistics
        if print_stats:
            print_combined_perm_stats(perm, perm_data)

        # if dump is enabled, write perm stats to file
        if dump:
            perm_data.sort(key=operator.itemgetter('pkg', 'ver'))
            dump_perm_stats(perm, perm_data)


def main():
    parser = argparse.ArgumentParser()
    # analysis type
    parser.add_argument("-l", "--list_auto_granted",
                        help="print all automatically granted permissions",
                        action="store_true")
    parser.add_argument("-e", "--list_api_evolution",
                        help="print results from api evolution analysis",
                        action="store_true")
    parser.add_argument("-m", "--print_mapping",
                        help="prints the androguard mappings, divided by perms",
                        action="store_true")
    parser.add_argument("-a", "--list_auto_granted_apis",
                        help="lists automatically granted APIS",
                        action="store_true")
    parser.add_argument("-f", "--list_auto_granted_flows",
                        help="lists automatically granted flows",
                        action="store_true")
    parser.add_argument("-c", "--combined_analysis",
                        help="lists combined statistics",
                        action="store_true")
    parser.add_argument("-p", "--print_stats",
                        help="prints the stats while performing an analysis",
                        action="store_true")
    parser.add_argument("-d", "--dump",
                        help="writes output of combined analysis to file",
                        action="store_true")
    parser.add_argument("-s", "--skip_prev_ver_enabler",
                        help="skips permissions enabled by previous version",
                        action="store_true")
    parser.add_argument("-t", "--target_dir",
                        help="specifies target dir in which data is")

    # read arguments
    args = parser.parse_args()

    if args.list_auto_granted:
        list_auto_granted(args.print_stats)
    if args.list_api_evolution:
        list_api_evolution(args.print_stats, args.target_dir)
    if args.print_mapping:
        print_mapping()
    if args.list_auto_granted_apis:
        list_auto_granted_apis(args.print_stats)
    if args.list_auto_granted_flows:
        list_auto_granted_flows(args.print_stats)
    if args.combined_analysis:
        combined_analysis(args.dump, args.print_stats, args.skip_prev_ver_enabler)


if __name__ == '__main__':
    main()
