# coding=utf-8
import json

import luigi
import matplotlib

matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.colors as colors
import numpy as np
import os
import pandas as pd
import seaborn as sns
import sys

sys.path.append("..")
import cfg

from constants import DANGEROUS_GROUPS

from collections import defaultdict


def get_label_src(label):
    ''' returns the flow source label '''
    return label.split(' - ')[0]


def get_label_sink(label):
    ''' returns the flow sink label '''
    return label.split(' - ')[1]


def get_base_src(label):
    ''' returns the base name of flow source (without lib location) '''
    return get_label_src(label).split(':')[0].strip()


def get_base_sink(label):
    ''' get base name of sink (without lib location) '''
    return get_label_sink(label).split(':')[0].strip()


def read_json_matrix(matrix_folder, pkg):
    ''' reads matrix and its labels from a json file and returns them '''
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


def read_app_info(pkg):
    pass


# returns the indexes (flow, version) where new flows appear
def get_new_flow_indexes(flow_data):
    matrix = flow_data['m']
    indexes = []
    for i in range(0, len(flow_data['l'])):
        prev_status = 0
        for j in range(0, len(flow_data['v'])):
            status = matrix[i][j]
            if (status > 0) and prev_status == 0:
                indexes.append((i, j))
            if status >= 0:
                prev_status = status
    return indexes


def get_perm_group(perm):
    for g, pl in DANGEROUS_GROUPS.items():
        if perm in pl:
            return g


def is_perm_automatically_granted(perm_matrix, perm_labels, version, perm):
    """ return true if a permission would be automatically granted for a
    specific version """
    # retrieve permission group
    group = get_perm_group(perm)

    # check other permissions in the group
    for p in DANGEROUS_GROUPS[group]:
        # skip the input permission
        if p == perm:
            continue

        # if the permission is in the permission matrix (in the permission
        # labels list) and it was granted in both previous and current
        # version, return true
        if p in perm_labels:
            index = perm_labels.index(p)
            if (perm_matrix[index][version] > 0 and
                    perm_matrix[index][version - 1]):
                return True

    return False


def check_perm(perm_matrix, perm_labels, version_index, perm):
    """ returns the status of a permission (newly asked, already asked or missing) """
    label_index = perm_labels.index(perm) if perm in perm_labels else -1
    if label_index < 0:
        return 'M'  # missing permission
    elif perm_matrix[label_index][version_index] == 0:
        if version_index > 0 and perm_matrix[label_index][version_index - 1] > 0:
            return 'R'  # revoked
        else:
            return 'M'  # missing permission
    elif version_index == 0:
        return 'N'  # newly asked permission
    elif perm_matrix[label_index][version_index - 1] == 0:
        if is_perm_automatically_granted(perm_matrix,
                                         perm_labels,
                                         version_index,
                                         perm):
            return 'G'  # newly asked and automatically granted
        else:
            return 'N'  # newly asked permission
    else:
        return 'A'  # already asked permission


def is_layout_changed(version, layout_data):
    """ returns True if layout matrix changed or added is not zero """
    # layout matrix has one less column than the flow ones, because
    # it compares 2 versions. if version is zero, we assume no changes
    # in the layout
    if version == 0:
        return True

    m = layout_data['m']
    if m[layout_data['l'].index('ui_added')][version - 1] > 0:
        return True
    else:
        return False


def get_list_perm_status(pm, pl, ver, perms_list):
    """ returns the permission status for sms flow (which checks READ_SMS,
    RECEIVE_SMS and RECEIVE_MMS permission status """
    status_list = []
    for p in perms_list:
        p_status = check_perm(pm, pl, ver, p)
        status_list.append(p_status)

        # if permission is ACCESS_FINE_LOCATION and it is
        # newly granted, return N independently of
        # ACCESS_COARSE_LOCATION permission status
        if p == 'ACCESS_FINE_LOCATION' and (p_status in ['N', 'G']):
            return p_status

    # if all elements are the same return that element
    if status_list.count(status_list[0]) == len(status_list):
        return status_list[0]

    # if we have only revoked and missing, return revoked
    elif ('R' in status_list and 'M' in status_list and 'G' not in status_list
          and 'N' not in status_list and 'A' not in status_list):
        return 'R'

    # if we have only newly added and missing, return newly added
    elif ('R' not in status_list and 'M' in status_list and
          ('N' in status_list or 'G' in status_list) and 'A' not in status_list):
        if 'G' in status_list:
            return 'G'
        else:
            return 'N'

    # if a permission was already asked and still is, return already asked
    elif 'A' in status_list:
        return 'A'

    # else we are in a special case: both newly asked and revoked permissions
    # and no already asked: return special case
    elif (('N' in status_list or 'G' in status_list) and
          'R' in status_list and not 'A' in status_list):
        return 'S'

    # else there is some error: return E
    else:
        return 'E'



def get_flow_perm_status(ind, perm_data, labels):
    """ returns the permission status of the input flow """
    # if perm_data is None we don't have the permission matrix
    # file, so we return '?'
    if perm_data is None:
        return '?'

    pm = perm_data['m']
    pl = perm_data['l']

    # flows requiring permission
    location_flow = 'ACCESS_LOCATION'
    contact_flow = 'READ_CONTACTS'
    account_id_flow = 'GET_ACCOUNTS'
    read_storage_flow = 'READ_EXTERNAL_STORAGE'
    unique_id_flow = 'READ_PHONE_STATE'
    sms_flow = 'RECEIVE_SMS'
    audio_id_flow = 'RECORD_AUDIO'

    label = labels[ind[0]]
    ver = ind[1]

    src = get_base_src(label)

    if src == location_flow:
        perm_status = get_list_perm_status(pm, pl, ver,
                                           ['ACCESS_FINE_LOCATION',
                                            'ACCESS_COARSE_LOCATION'])

    elif src == contact_flow:
        perm_status = check_perm(pm, pl, ver, 'READ_CONTACTS')

    elif src == unique_id_flow:
        perm_status = check_perm(pm, pl, ver, 'READ_PHONE_STATE')

    elif src == read_storage_flow:
        perm_status = get_list_perm_status(pm, pl, ver,
                                           ['READ_EXTERNAL_STORAGE',
                                            'WRITE_EXTERNAL_STORAGE'])

    elif src == audio_id_flow:
        perm_status = check_perm(pm, pl, ver, 'RECORD_AUDIO')

    elif src == account_id_flow:
        perm_status = check_perm(pm, pl, ver, 'GET_ACCOUNTS')

    elif src == sms_flow:
        perm_status = get_list_perm_status(pm, pl, ver, ['READ_SMS',
                                                         'RECEIVE_SMS',
                                                         'RECEIVE_MMS'])

    else:
        perm_status = '-'

    return perm_status


def flow_analysis(pkg):
    # read flow matrix
    flow_data = read_json_matrix(cfg.flow_appflow_matrix_folder, pkg)
    labels = flow_data['l']
    versions = flow_data['v']
    flow_matrix = flow_data['m']

    # read permission matrix
    perm_data = read_json_matrix(cfg.info_permission_matrix_folder, pkg)

    if perm_data is None:
        for i in range(0, 5):
            print('<<<<<<<<<< PERM_DATA is None >>>>>>>>>>')
            return None

    # if the shape of matrices differs there is a problem with versions
    #    if not flow_matrix.shape[1] == perm_data['m'].shape[1]:
    if perm_data is not None and not len(versions) == len(perm_data['v']):
        for i in range(0, 5):
            print('<<<<<<<<<< MATRIX SHAPE DIFFERS >>>>>>>>>>')
        print('flow has %d versions, perm_data has %d' % (len(versions),
                                                          len(perm_data['v'])))
        return None

    # read layout matrix
    layout_data = read_json_matrix(cfg.apktool_ui_matrix_folder, pkg)

    flow_indexes = get_new_flow_indexes(flow_data)
    flow_perm_status = []

    # create analysis matrix, color all cells with an info flow
    analysis_matrix = np.zeros(flow_matrix.shape)
    for i in range(0, analysis_matrix.shape[0]):
        for j in range(0, analysis_matrix.shape[1]):
            val = 1 if flow_matrix[i][j] > 0 else flow_matrix[i][j]
            analysis_matrix[i][j] = val

    character_matrix = np.empty(flow_matrix.shape, dtype='string')
    for i in range(0, character_matrix.shape[0]):
        for j in range(0, character_matrix.shape[1]):
            character_matrix[i][j] = ''

    # for each flow, update the analysis and character matrix
    # to build the analysis heatmap
    for ind in flow_indexes:
        label = labels[ind[0]]
        ver = versions[ind[1]]

        # get permission status when a new flow appears
        perm_status = get_flow_perm_status(ind, perm_data, labels)
        character_matrix[ind[0]][ind[1]] = perm_status

        # get layout status
        if layout_data is None:
            layout_changed = '?'
        else:
            layout_changed = 'T' if is_layout_changed(ind[1], layout_data) else 'F'
        layout_val_mapping = {'T': 1, '?': 2, 'F': 3}
        analysis_matrix[ind[0]][ind[1]] = layout_val_mapping[layout_changed]

        # create row for new flow
        row = '%s | %s (%s) %s' % (label, ver, perm_status, layout_changed)
        flow_perm_status.append(row)

        # analyze permission status until the end of the flow, and
        # only prent newly added or revoked
        for i in range(ind[1] + 1, len(versions)):
            if not flow_matrix[ind[0]][i] > 0:
                break
            perm_status = get_flow_perm_status((ind[0], i), perm_data, labels)

            if perm_status not in ['A', 'M', '-']:
                character_matrix[ind[0]][i] = perm_status

    # create heatmap folder if missing
    # TODO make heatmap the output of the luigi task
    if not os.path.exists(cfg.analysis_flow_heatmap_folder):
        os.makedirs(cfg.analysis_flow_heatmap_folder)
    create_heatmap(analysis_matrix, labels, versions, character_matrix, pkg)

    return flow_perm_status


def create_heatmap(data, row_labels, col_labels, char_matrix, pkg):
    """ creates the heatmap of permission use and saves it to a file """
    # seaborn
    dpi = 72.27
    fontsize_x_pt = 8
    fontsize_y_pt = 10
    # comput the matrix height in points and inches
    matrix_height_pt = fontsize_y_pt * data.shape[0]
    matrix_height_in = matrix_height_pt / dpi
    matrix_width_pt = fontsize_x_pt * data.shape[1]
    matrix_width_in = matrix_width_pt / dpi

    # compute the required figure height
    top_margin = 0.04  # in percentage of the figure height
    bottom_margin = 0.04  # in percentage of the figure height
    coeff = 2
    figure_height = coeff * matrix_height_in / (1 - top_margin - bottom_margin)
    figure_width = coeff * matrix_width_in / (1 - top_margin - bottom_margin)

    cm = plt.cm.get_cmap('gist_heat')  # plasma viridis
    cm = colors.LinearSegmentedColormap('hot_r', plt.cm.revcmap(cm._segmentdata))
    cm.set_under('blue')
    cm.set_bad('lightgray')
    pdata = pd.DataFrame(data, index=row_labels, columns=col_labels)

    pdata.index.name = "Flows"
    pdata.columns.name = "Versions"

    splot = sns.clustermap(pdata, col_cluster=False, row_cluster=False,
                           figsize=(figure_width, figure_height),
                           cmap=cm, vmin=0, vmax=3, annot=char_matrix,
                           annot_kws={'fontsize': 10}, fmt='')

    splot.cax.set_visible(False)
    plt.setp(splot.ax_row_dendrogram, visible=False)
    plt.setp(splot.ax_col_dendrogram, visible=False)
    splot.ax_heatmap.yaxis.set_ticks_position('left')
    splot.ax_heatmap.yaxis.set_label_position('left')
    splot.ax_heatmap.set_xlabel("Versions", fontsize=10)
    splot.ax_heatmap.set_ylabel("Flows", fontsize=10)

    splot.ax_heatmap.set_yticks(np.arange(data.shape[0]) + 0.5,
                                minor=False)
    plt.setp(splot.ax_heatmap.get_yticklabels(), rotation=0)
    plt.setp(splot.ax_heatmap.get_xticklabels(), rotation=90)
    plt.setp(splot.ax_heatmap.get_yticklabels(), fontsize=8)
    plt.setp(splot.ax_heatmap.get_xticklabels(), fontsize=6)

    splot.savefig(os.path.join(cfg.analysis_flow_heatmap_folder, pkg + '.pdf'),
                  format='pdf')


class ExternalFile(luigi.ExternalTask):
    ext_file = luigi.Parameter()

    def output(self):
        return luigi.LocalTarget(self.ext_file)


class PermAnalysis(luigi.Task):
    pkg = luigi.Parameter()

    def requires(self):
        perm_matrix = os.path.join(cfg.info_permission_matrix_folder,
                                   self.pkg, self.pkg + '.json')
        appflow_matrix = os.path.join(cfg.flow_appflow_matrix_folder,
                                      self.pkg, self.pkg + '.json')

        return {'perm_matrix': ExternalFile(ext_file=perm_matrix),
                'appflow_matrix': ExternalFile(ext_file=appflow_matrix)}

    def output(self):
        output_file = os.path.join(cfg.analysis_flow_folder,
                                   self.pkg + '.txt')
        return luigi.LocalTarget(output_file)

    def run(self):
        flow_perm_list = flow_analysis(self.pkg)
        if flow_perm_list is not None:
            with self.output().open('w') as data_file:
                json.dump(flow_perm_list, data_file)


class MatrixAnalysis(luigi.WrapperTask):
    """ WrapperTask to trigger analysis of FlowDroid matrices """

    def requires(self):

        apps = defaultdict(set)
        for root, dirs, files in os.walk(cfg.fake_apks_folder):
            for basename in files:
                if basename.endswith('.apk'):
                    pkg = "_".join(basename.split("_")[:-2])
                    apps[pkg].add(pkg)
        for pkg, apks in apps.items():
            yield PermAnalysis(pkg=pkg)


if __name__ == '__main__':
    luigi.run(main_task_cls=MatrixAnalysis)
