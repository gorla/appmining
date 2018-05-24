# coding=utf-8
import argparse
import json
import numpy as np
import os
import sys

import matrix_analysis

sys.path.append("..")
import cfg

from local_cfg import evo_data_folder
from collections import defaultdict


def get_label_src(label):
    """ returns the flow source label """
    return label.split(' - ')[0]


def get_label_sink(label):
    """ returns the flow sink label """
    return label.split(' - ')[1]


def get_src_lib(label):
    src_label = get_label_src(label)
    if ':' in src_label:
        return src_label.split(':')[1].strip()
    else:
        return None


def get_sink_lib(label):
    sink_label = get_label_sink(label)
    if ':' in sink_label:
        return sink_label.split(':')[1].strip()
    else:
        return None


def get_base_src(label):
    """ returns the base name of flow source (without lib location) """
    return get_label_src(label).split(':')[0].strip()


def get_base_sink(label):
    """ get base name of sink (without lib location) """
    return get_label_sink(label).split(':')[0].strip()


def read_json_matrix(matrix_folder, pkg):
    """ reads matrix and its labels from a json file and returns them """
    m_file = os.path.join(matrix_folder, pkg, pkg + '.json')
    # if matrix json file is missing return None
    if not os.path.exists(m_file):
        return None

    # else return the matrix with labels and versions
    else:
        with open(m_file) as data_file:
            data = json.load(data_file)

            matrix = np.array(data['m'])
            row_labels = data['yl']
            versions = data['xl']

            return {'m': matrix, 'l': row_labels, 'v': versions}


def get_all_pkgs():
    pkgs = set()

    # TODO temporary replacement for get_all_pkgs(): cycling all analysis
    # folders and getting all found packages
    target_dirs = [os.path.join(evo_data_folder, cfg.analysis_dns_folder),
                   os.path.join(evo_data_folder, cfg.analysis_stringoid_folder),
                   os.path.join(evo_data_folder, cfg.analysis_flow_folder)]
    for fldr in target_dirs:
        for (dirpath, dirnames, filenames) in os.walk(fldr):
            for filename in filenames:
                if filename.endswith('.txt'):
                    pkgs.add(filename[:-4])

    return pkgs


def is_np_src_or_sink(s):
    return s.startswith("NP") or s.startswith('ACCESS_NETWORK_STATE')


def filter_out_flow(src, sink, perm_status=None):
    return is_np_src_or_sink(src) or is_np_src_or_sink(sink) or perm_status == 'M'



def flow_count_stats(skip_np=False):
    """ prints the statistics regarding layout status """
    perm_stats = {'M': 0,
                  'N': 0,
                  'A': 0,
                  'R': 0,
                  'G': 0,
                  'S': 0,
                  '?': 0,
                  '-': 0}
    cha = 0
    not_c = 0
    unk = 0

    # user_invisible are flows for which layout is unchanged and permission
    # is either already requested or automatically granted
    user_invisible = 0

    for pkg in get_all_pkgs():
        filepath = os.path.join(evo_data_folder,
                                cfg.analysis_flow_folder,
                                pkg + '.txt')
        if not os.path.isfile(filepath):
            continue
        with open(filepath) as df:
            data = json.load(df)
            for i in data:

                src = get_base_src(i)
                sink = get_base_sink(i)

                layout = i[-1]
                perm = i[-4]

                # if skip_np is True, skip all flows starting with NP
                if skip_np and filter_out_flow(src, sink, perm):
                    continue

                if perm == 'G':
                    print('G >>> %s |  %s' % (pkg, i))

                # if the permission is already requested or automatically
                # granted and there are no changes in layout, update the
                # user_invisible stats
                if (perm == 'G' or perm == 'A') and layout == 'F':
                    user_invisible += 1

                perm_stats[perm] += 1

                if layout == '?':
                    unk += 1
                elif layout == 'T':
                    cha += 1
                elif layout == 'F':
                    not_c += 1

    # print stats
    tot = cha + not_c + unk
    print('flows total:  ' + str(tot))
    print('perm missing: %d (%.2f)' % (perm_stats['M'],
                                       100.0 * perm_stats['M'] / tot))
    print('perm already asked: %d (%.2f)' % (perm_stats['A'],
                                             100.0 * perm_stats['A'] / tot))
    print('perm newly asked: %d (%.2f)' % (perm_stats['N'],
                                           100.0 * perm_stats['N'] / tot))
    print('perm revoked: %d (%.2f)' % (perm_stats['R'],
                                       100.0 * perm_stats['R'] / tot))
    print('perm not required: %d (%.2f)' % (perm_stats['-'],
                                            100.0 * perm_stats['-'] / tot))
    print('perm unknown(no perm matrix): %d (%.2f)' % (perm_stats['?'],
                                                       100.0 * perm_stats['?'] / tot))
    print('perm newly asked auto-granted: %d (%.2f)' % (perm_stats['G'],
                                                        100.0 * perm_stats['G'] / tot))
    print('perm special state: %d (%.2f)' % (perm_stats['S'],
                                             100.0 * perm_stats['S'] / tot))
    print('layout changed: %d (%.2f)' % (cha, 100.0 * float(cha) / tot))
    print('layout not changed: %d (%.2f)' % (not_c, 100.0 * float(not_c) / tot))
    print('layout unknown: %d (%.2f)' % (unk, 100.0 * float(unk) / tot))

    print('user-invisible flows: %d (%.2f)' % (user_invisible,
                                               100.0 * float(user_invisible) / tot))


def print_all_flows_src(skip_np=False):
    nlib_src = 0
    lib_src = 0
    app_src = 0
    src_count = 0

    src_set = set()
    sink_set = set()
    for pkg in get_all_pkgs():
        filepath = os.path.join(evo_data_folder,
                                cfg.analysis_flow_folder,
                                pkg + '.txt')
        if not os.path.isfile(filepath):
            continue
        with open(filepath) as df:
            data = json.load(df)

            for flow in data:

                src = get_label_src(flow.split(' | ')[0]).strip()
                src_set.add(src)

                sink = get_label_sink(flow.split(' | ')[0]).strip()
                sink_set.add(sink)

                perm_status = flow[-4]

                # if skip_np is True, skip all flows starting with NP
                if skip_np and filter_out_flow(src, sink, perm_status):
                    continue

                if ':' in src:
                    if src.endswith(':nlib'):
                        nlib_src += 1
                    else:
                        lib_src += 1

                else:
                    app_src += 1
                src_count += 1

    print('>>>>>>> FLOW SOURCES <<<<<<<')
    for s in src_set:
        print(s)

    print('>>>>>>> FLOW SINKS <<<<<<<')
    for s in sink_set:
        print(s)

    print('nlib sources: %d (%.2f)' % (nlib_src, 100.0 * nlib_src / src_count))
    print('lib sources: %d (%.2f)' % (lib_src, 100.0 * lib_src / src_count))
    print('app sources: %d (%.2f)' % (app_src, 100.0 * app_src / src_count))
    print('total flows: %d' % src_count)


def get_flow_perm_status(src, sink, ver, flow_analysis_data):
    """ returns the flow permission status of input flow, identified by
    src, sink and version """
    # find the flow corresponding to src, sink and version
    # inside flow_analysis_data, and return permission status
    found = False
    perm_status = None
    for flow_data in flow_analysis_data:
        flow_name = flow_data.split(' | ')[0]
        if (src == get_base_src(flow_name) and
                sink == get_base_sink(flow_name) and
                ver == flow_data.split(' | ')[1].split(' ')[0]):

            # this check has been placed in the code because there could be
            # the case where two flows have the same source, sink and version,
            # but are originated from different libraries. In theory it should
            # never be reached as the flows should be related to the same
            # permission, thus having the same permission status: we could then
            # returning the first permission status encountered
            if found and flow_data[-4] != perm_status:
                print('################################')
                print('ERROR: there are multiple missing permission status')
                print('for this flow: check code get_flow_perm_status()')
                print('%s  %s  %s' % (src, sink, ver))
                print(flow_analysis_data)
                print('################################')
                raise MultiplePermissionStatusException()

            perm_status = flow_data[-4]
            found = True

    if perm_status is None:
        print('*** error ing get_flow_perm_status(): FLOW NOT FOUND *** ')
        raise FlowNotFoundException()
    return perm_status


def print_src_stats(skip_np=False):
    total_flows = 0
    already_leaked_src = 0

    for pkg in get_all_pkgs():
        flow_analysis_filepath = os.path.join(evo_data_folder,
                                              cfg.analysis_flow_folder,
                                              pkg + '.txt')
        if not os.path.isfile(flow_analysis_filepath):
            print('error in flow_analysis filepath')
        with open(flow_analysis_filepath) as df:
            flow_analysis_data = json.load(df)

        filepath = os.path.join(evo_data_folder,
                                cfg.flow_appflow_matrix_folder,
                                pkg, pkg + '.json')
        if not os.path.isfile(filepath):
            continue
        with open(filepath) as df:
            data = json.load(df)

            flows = data['yl']
            matrix = data['m']
            versions = data['xl']
            for i in range(0, len(flows)):
                if flows[i] == 'No flows':
                    continue

                src = get_base_src(flows[i])
                sink = get_base_sink(flows[i])

                # if skip_np is True, skip all flows starting with NP
                if skip_np and filter_out_flow(src, sink):
                    continue

                for j in range(1, len(versions)):
                    # for each new flow, check if source is already
                    # being leaked in another flow
                    if matrix[i][j] > 0 and matrix[i][j - 1] == 0:
                        perm_status = get_flow_perm_status(src, sink,
                                                           versions[j],
                                                           flow_analysis_data)
                        if perm_status == 'M':
                            continue

                        total_flows += 1
                        for index in range(0, len(flows)):
                            # skip current index
                            if index == i:
                                continue

                            index_src = get_base_src(get_base_src(flows[index]))
                            if (matrix[index][j] > 0 and
                                    matrix[index][j - 1] > 0 and
                                    src == index_src):
                                already_leaked_src += 1
                                break

    print('total flows (except first version): %d' % total_flows)

    new_src = total_flows - already_leaked_src
    already_leaked_pct = 100.0 * already_leaked_src / total_flows
    new_src_pct = 100.0 * new_src / total_flows
    print('new sources: %d (%.2f)' % (new_src, new_src_pct))
    print('already leaked sources %d (%.2f)' % (already_leaked_src,
                                                already_leaked_pct))


def most_used_flows(skip_np=False):
    """ print most used flow stats """
    flow_dict = defaultdict(int)
    flow_num = defaultdict(int)
    lib_dict = defaultdict(int)
    lib_total_count = 0
    avg_flow_count = 0
    total_count = 0
    app_with_flows = 0
    app_without_flows = 0
    app_flowdroid_crash = 0
    total_flowdroid_crash_num = 0
    for pkg in get_all_pkgs():
        filepath = os.path.join(evo_data_folder,
                                cfg.flow_appflow_base_matrix_folder,
                                pkg, pkg + '.json')
        if not os.path.isfile(filepath):
            continue
        with open(filepath) as df:
            data = json.load(df)
            flows = data['yl']
            matrix = data['m']
            vers = data['xl']
            app_with_flows += 1

            for i in range(0, len(flows)):
                flow_name = flows[i]
                # if there are now flows continue
                if flow_name == 'No flows':
                    app_without_flows += 1
                    app_with_flows -= 1
                    crash_num = 0.0
                    for j in range(0, len(vers)):
                        if matrix[i][j] < 0:
                            crash_num += 1
                    if crash_num / len(vers) > 0.5:
                        print('PKG: %s crash num: %d - %d vers' % (pkg, crash_num, len(vers)))
                        app_flowdroid_crash += 1
                    continue

                # compose flow name without libraries
                src = get_base_src(flow_name)
                sink = get_base_sink(flow_name)
                f = src + ' - ' + sink

                # if skip_np is True, skip all flows starting with NP
                if skip_np and filter_out_flow(src, sink):
                    continue

                # count how many times flow appears
                count = 0
                for j in range(0, len(vers)):
                    if matrix[i][j] > 0:
                        count += matrix[i][j]
                        total_count += matrix[i][j]
                        flow_num[count] += 1
                    if matrix[i][j] < 0:
                        total_flowdroid_crash_num += 1

                    if j > 0 and matrix[i][j] >= 0:
                        avg_flow_count += matrix[i][j] - matrix[i][j - 1]

                # count which is the lib with most flows
                src_lib = get_src_lib(flow_name)
                if src_lib is not None:
                    lib_dict[src_lib] += 1
                    lib_total_count += 1
                sink_lib = get_sink_lib(flow_name)
                if sink_lib is not None:
                    lib_dict[sink_lib] += 1
                    lib_total_count += 1

                # update count
                flow_dict[f] += count

    for l in sorted(lib_dict, key=lib_dict.get, reverse=True):
        print('%s: %d (%.2f)' % (l, lib_dict[l],
                                 100.0 * lib_dict[l] / lib_total_count))

    print('Total # of flows: %d' % total_count)
    for w in sorted(flow_dict, key=flow_dict.get, reverse=True):
        print('%s: %d (%.2f)' % (w, flow_dict[w],
                                 100.0 * flow_dict[w] / total_count))
    print('Avg flow change: %d (avg %.4f)' % (avg_flow_count,
                                              1.0 * avg_flow_count / 14645))
    print('Apps with flows: %d' % (app_with_flows))
    print('apps without flows: %d' % (app_without_flows))
    print('flowdroid app crash: %d' % (app_flowdroid_crash))
    print('totak flowdroid apk crash: %d' % (total_flowdroid_crash_num))

    low = 0
    high = 0
    # print how many flows are low or high count
    for w in sorted(flow_num, key=flow_num.get, reverse=True):
        if w < 10:
            low += flow_num[w]
        else:
            high += flow_num[w]
    print('low: %s - high: %s' % (low, high))


''' %%%%%%%%%% PATTERNS %%%%%%%%%% '''


# returns the flow status
def get_flow_status(flow_count, binary):
    if flow_count == 0:
        return '0'
    elif flow_count > 10 and not binary:
        return '2'
    else:
        return '1'


def patterns(binary=False):
    """ print patterns of flows. We use the following legenda:
        0 - flow does not appear
        1 - flow appears with low number of instances
        2 - flow appears with high number of instances """
    fd = defaultdict(int)
    flow_count = 0
    for pkg in get_all_pkgs():
        filepath = os.path.join(evo_data_folder,
                                cfg.flow_appflow_base_matrix_folder,
                                pkg, pkg + '.json')
        if not os.path.isfile(filepath):
            continue
        with open(filepath) as df:
            data = json.load(df)
            flows = data['yl']
            matrix = data['m']
            vers = data['xl']
            for i in range(0, len(flows)):
                # if there are now flows continue
                flow_name = flows[i]

                # if there are no flows continue
                if flow_name == 'No flows':
                    continue

                # check if it's a lib flow (both src and sink in lib)
                is_lib_flow = (get_src_lib(flow_name) is not None and
                               get_sink_lib(flow_name) is not None)

                current_status = -1
                flow_status = []
                for j in range(0, len(vers)):
                    status = get_flow_status(matrix[i][j], binary)
                    if status != current_status:
                        flow_status.append(status)
                        current_status = status
                fd['-'.join(flow_status)] += 1
                flow_count += 1

    for f in sorted(fd, key=fd.get, reverse=True):
        print('%s   %d (%.2f)' % (f, fd[f], 100.0 * fd[f] / flow_count))
    print('total number of flows: %d' % flow_count)

    zz = zs = sz = ss = 0
    for f, c in fd.items():
        if f.startswith('0') and f.endswith('0'):
            zz += c
        elif f.startswith('0') and not f.endswith('0'):
            zs += c
        elif not f.startswith('0') and f.endswith('0'):
            sz += c
        elif not f.startswith('0') and not f.endswith('0'):
            ss += c
    print('0 > * > 0: %d (%.2f)' % (zz, 100.0 * zz / flow_count))
    print('1+ > * > 0: %d (%.2f)' % (sz, 100.0 * sz / flow_count))
    print('0 > * > 1+: %d (%.2f)' % (zs, 100.0 * zs / flow_count))
    print('1+ > * > 1+: %d (%.2f)' % (ss, 100.0 * ss / flow_count))


''' %%%%%%%%%% DOMAIN STATS %%%%%%%%%% '''


def update_layout_stats(layout, pkg, analysis_folder):
    """ updates input layout dictionary with layout stats """
    analysis_file = os.path.join(analysis_folder,
                                 pkg + '.txt')
    if not os.path.isfile(analysis_file):
        return
    with open(analysis_file) as df:
        dns_data = json.load(df)

    # count num of layout changed T/F
    for analysis in dns_data:
        layout_status = analysis[-1]
        layout[layout_status] += 1


def update_flow_stats(flow_stats, pkg, analysis_folder, matrix_folder):
    """ updates input flow_stats dictionary with flow stats """
    matrix_file = os.path.join(matrix_folder, pkg,
                               pkg + '.json')
    if not os.path.isfile(matrix_file):
        return
    with open(matrix_file) as df:
        flow_data = json.load(df)

    analysis_file = os.path.join(analysis_folder,
                                 pkg + '.txt')
    if not os.path.isfile(analysis_file):
        return
    with open(analysis_file) as df:
        dns_data = json.load(df)

    # count num of new flows when a new domain appears
    for analysis in dns_data:
        version = analysis.split('(')[-1].split(')')[0]

        # if version is in the format ver-yyyy-mm-dd or ver~year
        # only take the version part
        if '-' in version:
            version = version[:version.index('-')]
        if '~' in version:
            version = version[:version.index('~')]

        ver_index = flow_data['xl'].index(version)
        stat = 'M'
        for i in range(0, len(flow_data['yl'])):
            if (i > 0 and flow_data['m'][i][ver_index] > 0 and
                    flow_data['m'][i][ver_index - 1] == 0):
                stat = 'N'
                break
            elif flow_data['m'][i][ver_index] > 0:
                stat = 'A'

        flow_stats[stat] += 1


def domain_stats():
    dns_layout = {'T': 0, 'F': 0, '?': 0}
    dns_flow = {'N': 0, 'A': 0, 'M': 0}
    stringoid_layout = {'T': 0, 'F': 0, '?': 0}
    stringoid_flow = {'N': 0, 'A': 0, 'M': 0}

    for pkg in get_all_pkgs():
        # DNS analysis
        update_layout_stats(dns_layout, pkg,
                            os.path.join(evo_data_folder,
                                         cfg.analysis_dns_folder))
        update_flow_stats(dns_flow, pkg,
                          os.path.join(evo_data_folder,
                                       cfg.analysis_dns_folder),
                          os.path.join(evo_data_folder,
                                       cfg.flow_appflow_matrix_folder))

        # stringoid analysis
        update_layout_stats(stringoid_layout, pkg,
                            os.path.join(evo_data_folder,
                                         cfg.analysis_stringoid_folder))
        update_flow_stats(stringoid_flow, pkg,
                          os.path.join(evo_data_folder,
                                       cfg.analysis_stringoid_folder),
                          os.path.join(evo_data_folder,
                                       cfg.flow_appflow_matrix_folder))

    print('dns layout changed stats: %s tot:%d' % (str(dns_layout),
                                                   sum(dns_layout.values())))
    print('dns flow stats: %s tot:%d' % (str(dns_flow),
                                         sum(dns_flow.values())))

    print('stringoid layout changed stats: %s tot:%d' % (str(stringoid_layout),
                                                         sum(stringoid_layout.values())))
    print('stringoid flow stats: %s tot:%d' % (str(stringoid_flow),
                                               sum(stringoid_flow.values())))


''' %%%%%%%%%% LIBRARY STATISTICS %%%%%%%%%% '''


def lib_stats(skip_np=True):
    """ print lib stats for sources """
    libs = {}
    total_count = 0
    for pkg in get_all_pkgs():
        filepath = os.path.join(evo_data_folder,
                                cfg.flow_appflow_base_matrix_folder,
                                pkg, pkg + '.json')
        if not os.path.isfile(filepath):
            continue
        with open(filepath) as df:
            data = json.load(df)
            flows = data['yl']

            for i in range(0, len(flows)):
                flow_name = flows[i]
                # if there are no flows continue
                if flow_name == 'No flows':
                    continue

                # get library if present
                src_lib = get_src_lib(flow_name)
                if src_lib is not None:
                    # source to lib count
                    src = get_base_src(flow_name)
                    sink = get_base_sink(flow_name)
                    if skip_np and (is_np_src_or_sink(src) or
                                    is_np_src_or_sink(sink)):
                        continue

                    # add elements do dict if they are not present
                    if src_lib not in libs.keys():
                        libs[src_lib] = {}
                    if src not in libs[src_lib].keys():
                        libs[src_lib][src] = 0

                    # update count
                    libs[src_lib][src] += 1
                    total_count += 1

    src_stats = {}
    # print lib stats
    for lib, stats in libs.items():
        for src, c in stats.items():
            print('%s - %s: %d' % (lib, src, c))
            if src not in src_stats:
                src_stats[src] = c
            else:
                src_stats[src] = src_stats[src] + c

    print('total number of flow sources: %d' % (total_count))
    print('source stats for libraries:')
    for k, v in src_stats.items():
        print(k + ' - ' + str(v))


def flow_stats(skip_np=True):
    # compute matrix folder for flows
    matrix_folder = os.path.join(evo_data_folder,
                                 cfg.flow_appflow_base_matrix_folder)

    flows_in_first_ver = 0
    # variables to count added and removed flows
    added = 0
    removed = 0

    # cycle all packages
    for pkg in get_all_pkgs():

        # extract data from matrix
        flow_data = matrix_analysis.read_json_matrix(matrix_folder,
                                                     pkg)
        flow_matrix = flow_data['m']
        labels = flow_data['l']

        # skip apps with no flows
        if len(labels) == 1 and labels[0] == 'No flows':
            continue

        # cycle all flows
        for i in range(flow_matrix.shape[0]):
            # skip np flows if variable is true
            if skip_np and (is_np_src_or_sink(get_base_src(labels[i])) or
                            is_np_src_or_sink(get_base_sink(labels[i]))):
                continue

            flow_active = flow_matrix[i][0]
            if flow_active > 0:
                flows_in_first_ver += 1
            for j in range(1, flow_matrix.shape[1]):

                if flow_matrix[i][j] < 0:
                    # skip flowdroid crash versions
                    continue
                elif flow_active > flow_matrix[i][j]:
                    # flow removed
                    removed += flow_active - flow_matrix[i][j]
                    flow_active = flow_matrix[i][j]
                elif flow_active < flow_matrix[i][j]:
                    # flow added
                    added += flow_matrix[i][j] - flow_active
                    flow_active = flow_matrix[i][j]

    print('added flows: %d' % added)
    print('removed flows: %d' % removed)
    print('flows in first version: %d' % flows_in_first_ver)


def main():
    parser = argparse.ArgumentParser()
    # analysis type
    parser.add_argument("-f", "--flow_src",
                        help="print all flow sources",
                        action="store_true")
    parser.add_argument("-c", "--count_stats",
                        help="print layout and permission statistics",
                        action="store_true")
    parser.add_argument("-m", "--most_used_flows",
                        help="print most used flows stats",
                        action="store_true")
    parser.add_argument("-p", "--patterns",
                        help="print most used  patterns (allows binary).",
                        action="store_true")
    parser.add_argument('-d', '--domain',
                        help="print domains statistics",
                        action="store_true")
    parser.add_argument('-l', '--libs',
                        help="print libraries statistics",
                        action="store_true")
    parser.add_argument('-s', '--flow_stats',
                        help="print flow statistics",
                        action="store_true")

    # analysis options
    parser.add_argument('-b', "--binary",
                        help='triggers binary analysis',
                        action="store_true")

    # read arguments
    args = parser.parse_args()

    if args.flow_src:
        print_all_flows_src(skip_np=True)
        print_src_stats(skip_np=True)
    if args.count_stats:
        flow_count_stats(skip_np=True)
    if args.most_used_flows:
        most_used_flows(skip_np=False)
    if args.patterns:
        patterns(args.binary)
    if args.domain:
        domain_stats()
    if args.libs:
        lib_stats()
    if args.flow_stats:
        flow_stats(skip_np=True)


if __name__ == '__main__':
    main()
