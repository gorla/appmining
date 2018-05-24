import matplotlib
import numpy
import pandas as pd

matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.colors as colors

# try:
#     pkg_resources.require("seaborn==0.9.dev.k")
# except pkg_resources.VersionConflict:
#     print ("WARNING: using non-customised version of seaborn")
import seaborn as sns


def plot_heatmap(data, vmin=0, vmax=100, cm=None, col_colors=None,
                 row_colors=None, sorted_labels=None, annot=True,
                 col_cluster=False, row_cluster=False):
    # seaborn
    dpi = 72.27
    fontsize_x_pt = 8
    fontsize_y_pt = 10

    # compute the matrix height in points and inches
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
    ccr = 0.8 * col_colors.shape[0] / figure_height if col_colors is not None else 0
    # build the figure instance with the desired height
    # comput the matrix height in points and inches
    if cm is None:
        cm = plt.cm.get_cmap('gist_heat')  # plasma viridis
        cm = colors.LinearSegmentedColormap('hot_r', plt.cm.revcmap(cm._segmentdata))
        cm.set_bad('lightgray')
        cm.set_under('blue')
    if sorted_labels is not None:
        data = data.ix[sorted_labels]
    if sns.__version__ == "0.9.dev0+k":
        splot = sns.clustermap(data, col_cluster=col_cluster, row_cluster=row_cluster,
                               figsize=(figure_width, figure_height),
                               col_colors=col_colors, row_colors=row_colors,
                               cmap=cm, mask=(data == 0), vmin=vmin, vmax=vmax,
                               col_colors_ratio=ccr, xticklabels=1,  # print all labels
                               annot=annot, annot_kws={'fontsize': 3}, fmt='.2f')
    else:
        splot = sns.clustermap(data, col_cluster=col_cluster, row_cluster=row_cluster,
                               figsize=(figure_width, figure_height),
                               col_colors=col_colors, row_colors=row_colors,
                               cmap=cm, mask=(data == 0), vmin=vmin, vmax=vmax,
                               annot=annot, annot_kws={'fontsize': 3}, fmt='.2f',
                               xticklabels=1  # print all labels
                               )

    splot.cax.set_visible(False)  # TODO
    plt.setp(splot.ax_row_dendrogram, visible=False)  # TODO
    plt.setp(splot.ax_col_dendrogram, visible=False)  # TODO
    splot.ax_heatmap.yaxis.set_ticks_position('left')
    splot.ax_heatmap.yaxis.set_label_position('left')
    splot.ax_heatmap.set_xlabel(data.columns.name, fontsize=10)
    splot.ax_heatmap.set_ylabel(data.index.name, fontsize=10)

    splot.ax_heatmap.set_yticks(numpy.arange(data.shape[0]) + 0.5, minor=False)
    plt.setp(splot.ax_heatmap.get_yticklabels(), rotation=0)
    plt.setp(splot.ax_heatmap.get_xticklabels(), rotation=90)
    plt.setp(splot.ax_heatmap.get_yticklabels(), fontsize=8)
    plt.setp(splot.ax_heatmap.get_xticklabels(), fontsize=6)
    return splot


def get_col_colors(col_labels, app_info):
    # initializing col_colors, the first column is always white
    col_colors = ['white']

    # for each column name we check if the version name is the same
    # as the one of the previous version, in that case we put a red flag.
    # if the versionName has a major change, we put a green flag
    for i in range(1, len(col_labels)):
        actual_vn = app_info[col_labels[i]]['versionName'] if 'versionName' in app_info[col_labels[i]] else '0'
        previous_vn = app_info[col_labels[i - 1]]['versionName'] if 'versionName' in app_info[
            col_labels[i - 1]] else '0'
        if actual_vn == previous_vn:
            col_colors.append('red')
            continue
        a_split = actual_vn.split('.')
        p_split = previous_vn.split('.')
        # if the versioning format changed use a yellow flag
        if len(a_split) != len(p_split):
            col_colors.append('yellow')
        # if the first part of version changed flag green
        elif len(a_split) > 1 and a_split[0] != p_split[0]:
            col_colors.append('green')
        # if there are at least 2 dots, if the second part of
        # the version changes flag light green
        elif len(a_split) > 2 and len(p_split) > 2 and a_split[1] != p_split[1]:
            col_colors.append('lightgreen')
        # else use default color (white)
        else:
            col_colors.append('white')
    # return col_colors list just created
    return pd.DataFrame.from_dict({'v': col_colors})
