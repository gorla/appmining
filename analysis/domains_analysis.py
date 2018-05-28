# coding=utf-8
import luigi
import json
import matplotlib.pyplot as plt
import matplotlib.colors as colors
import numpy as np
import os
import pandas as pd
import seaborn as sns
import sys

sys.path.append("..")
import cfg
from collections import defaultdict


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


def get_analysis_indexes(data):
    """ returns the indexes (label, version) where new label appear """
    matrix = data['m']
    indexes = []
    for i in range(0, len(data['l'])):
        for j in range(0, len(data['v'])):
            if (matrix[i][j] > 0) and (j == 0 or matrix[i][j - 1] == 0):
                indexes.append((i, j))
    return indexes




def is_layout_changed(version, layout_data):
    """ returns True if layout matrix changed or added is not zero """
    # layout matrix has one less column than the index ones, because
    # it compares 2 versions. if version is zero, we assume no changes
    # in the layout
    if version == 0:
        return False

    m = layout_data['m']
    if m[layout_data['l'].index('changed')][version - 1] > 0 or \
            m[layout_data['l'].index('added')][version - 1] > 0:
        return True
    else:
        return False


def layout_analysis(pkg, matrix_folder, heatmap_file):
    # read matrices
    stringoid_data = read_json_matrix(matrix_folder, pkg)
    labels = stringoid_data['l']
    versions = stringoid_data['v']

    layout_data = read_json_matrix(cfg.apktool_layout_matrix_folder, pkg)

    # checking if label and stringoid matrix analyze the same versions
    if layout_data is not None:
        if stringoid_data['m'].shape[1] != layout_data['m'].shape[1] + 1:
            for i in range(0, 5):
                print('%%%%%%%%% MATRIX SIZE DIFFERS ' + pkg + ' %%%%%%%%%')
            return None

    indexes = get_analysis_indexes(stringoid_data)
    status = []

    analysis_matrix = np.zeros(stringoid_data['m'].shape)
    for i in range(0, analysis_matrix.shape[0]):
        for j in range(0, analysis_matrix.shape[1]):
            analysis_matrix[i][j] = stringoid_data['m'][i][j]

    character_matrix = np.empty(stringoid_data['m'].shape, dtype='string')
    for i in range(0, character_matrix.shape[0]):
        for j in range(0, character_matrix.shape[1]):
            character_matrix[i][j] = ''

    for ind in indexes:
        label = labels[ind[0]]
        ver = stringoid_data['v'][ind[1]]

        if layout_data is None:
            layout_changed = '?'
        else:
            layout_changed = 'T' if is_layout_changed(ind[1], layout_data) else 'F'

        row = '%s (%s) %s' % (label, ver, layout_changed)
        status.append(row)

        character_matrix[ind[0]][ind[1]] = layout_changed

    create_heatmap(analysis_matrix, labels, versions, character_matrix, heatmap_file)

    return status


def create_heatmap(data, row_labels, col_labels, char_matrix, filename):
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
    cm.set_bad('lightgray')
    pdata = pd.DataFrame(data, index=row_labels, columns=col_labels)

    pdata.index.name = "Domain"
    pdata.columns.name = "Versions"
    #    app_info = self.get_app_info()
    #    col_colors = self.get_col_colors(col_labels, app_info)

    splot = sns.clustermap(pdata, col_cluster=False, row_cluster=False,
                           figsize=(figure_width, figure_height),
                           cmap=cm, vmin=0, vmax=2,
                           annot=char_matrix, annot_kws={'fontsize': 10}, fmt='')

    splot.cax.set_visible(False)
    plt.setp(splot.ax_row_dendrogram, visible=False)
    plt.setp(splot.ax_col_dendrogram, visible=False)
    splot.ax_heatmap.yaxis.set_ticks_position('left')
    splot.ax_heatmap.yaxis.set_label_position('left')
    splot.ax_heatmap.set_xlabel("Versions", fontsize=10)
    splot.ax_heatmap.set_ylabel("Domain", fontsize=10)

    splot.ax_heatmap.set_yticks(np.arange(data.shape[0]) + 0.5,
                                minor=False)
    plt.setp(splot.ax_heatmap.get_yticklabels(), rotation=0)
    plt.setp(splot.ax_heatmap.get_xticklabels(), rotation=90)
    plt.setp(splot.ax_heatmap.get_yticklabels(), fontsize=8)
    plt.setp(splot.ax_heatmap.get_xticklabels(), fontsize=6)

    splot.savefig(filename, format='pdf')


class DnsAnalysis(luigi.Task):
    pkg = luigi.Parameter()

    def requires(self):
        m_file = os.path.join(cfg.dynamic_matrix_folder,
                              self.pkg, self.pkg + '.json')
        return ExternalFile(ext_file=m_file)

    def output(self):
        output_file = os.path.join(cfg.analysis_dns_folder,
                                   self.pkg + '.txt')
        return luigi.LocalTarget(output_file)

    def run(self):
        # create heatmap dir if missing
        heatmap_dir = cfg.analysis_dns_heatmap_folder
        if not os.path.exists(heatmap_dir):
            os.makedirs(heatmap_dir)
        heatmap_file = os.path.join(heatmap_dir, self.pkg + '.pdf')

        with self.output().open('w') as data_file:
            json.dump(layout_analysis(self.pkg, cfg.dynamic_matrix_folder,
                                      heatmap_file), data_file)


class StringoidAnalysis(luigi.Task):
    pkg = luigi.Parameter()

    def requires(self):
        m_file = os.path.join(cfg.stringoid_matrix_folder,
                              self.pkg, self.pkg + '.json')
        return ExternalFile(ext_file=m_file)

    def output(self):
        output_file = os.path.join(cfg.analysis_stringoid_folder,
                                   self.pkg + '.txt')
        return luigi.LocalTarget(output_file)

    def run(self):
        # create heatmap dir if missing
        heatmap_dir = cfg.analysis_stringoid_heatmap_folder
        if not os.path.exists(heatmap_dir):
            os.makedirs(heatmap_dir)
        heatmap_file = os.path.join(heatmap_dir, self.pkg + '.pdf')

        analysis_result = layout_analysis(self.pkg,
                                          cfg.stringoid_matrix_folder,
                                          heatmap_file)
        if analysis_result is not None:
            with self.output().open('w') as data_file:
                json.dump(analysis_result, data_file)




class ExternalFile(luigi.ExternalTask):
    """ Represents an external file for the Luigi pipeline """
    ext_file = luigi.Parameter()

    def output(self):
        return luigi.LocalTarget(self.ext_file)



class MatrixAnalysis(luigi.WrapperTask):
    """ WrapperTask to trigger analysis of Domain matrices """

    def requires(self):

        apps = defaultdict(set)
        target_folders = [cfg.fake_apks_folder]
        for f in target_folders:
            for root, dirs, files in os.walk(f):
                for basename in files:
                    if basename.endswith('.apk'):
                        pkg = "_".join(basename.split("_")[:-2])
                        vercode = basename.split("_")[-2]
                        date = basename.split("_")[-1].split('.')[0]
                        apps[pkg].add((pkg, vercode, date))
        for pkg, apks in apps.items():
            yield StringoidAnalysis(pkg=pkg)
            yield DnsAnalysis(pkg=pkg)


if __name__ == '__main__':
    luigi.run(main_task_cls=MatrixAnalysis)
