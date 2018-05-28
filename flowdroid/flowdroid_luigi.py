# TODO PhaseOptions.v().setPhaseOption("jb.tr", "ignore-wrong-staticness:true");
import csv
import json
import logging

import luigi
import matplotlib

matplotlib.use('Agg')
import numpy
import os
import subprocess
import sys
import pandas as pd
import pkg_resources

# check python version
if sys.version_info[0] != 2:
    raise Exception("The script has been developed for Python 2.7")

try:
    pkg_resources.require("seaborn==0.9.dev.k")
except pkg_resources.VersionConflict:
    print("WARNING: using non-customised version of seaborn")
    import seaborn
# !!! use pip install -e git+git+https://github.com/k-o-n-s-t/seaborn.git@trunk#egg=seaborn --user
# !!! to get custom version of seaborn
import sys

sys.path.append("..")
import cfg
import flowdroid_dispatcher as fl
import heatmaps
import lib_utils

from commons import commons
from targets import ExternalFileTarget, ApkFile, ExternalFile
from collections import defaultdict

logger = logging.getLogger('luigi-interface')


class ICRun(luigi.Task):
    file_name = luigi.Parameter()

    apks_folder = luigi.Parameter()
    app_info_folder = luigi.Parameter()
    ic3_cmd = luigi.Parameter()
    android_platform = luigi.Parameter()

    def __init__(self, *args, **kwargs):
        super(ICRun, self).__init__(*args, **kwargs)
        self.pkg, self.vercode, self.date = commons().get_apk_data(self.file_name)

    def requires(self):
        return ApkFile(file_name=self.file_name)

    def output(self):
        output_file = os.path.join(cfg.flow_ic3_model_folder,
                                   self.pkg,
                                   self.pkg + "_" +
                                   self.vercode + "_" +
                                   self.date + "_log.txt")
        return ExternalFileTarget(output_file)

    def run(self):
        apk_info_file = os.path.join(self.app_info_folder, self.pkg, self.pkg + '.json')
        with open(apk_info_file) as data_file:
            app_info = json.load(data_file)
        android_ver = app_info[self.vercode]['targetSdkVersion']
        android_path = os.path.join(self.android_platform, "android-" + android_ver, "android.jar")
        logger.info('Running IC3 on apk ' + self.file_name)
        # creating the out dir if it does not exist
        if not os.path.exists(os.path.dirname(self.output().path)):
            os.makedirs(os.path.dirname(self.output().path))
            # preparing the command to run:
            # 1) cd to flowdroid folder
        #        cd_cmd = 'cd ' + self.ic3_folder + ';'

        # 2) concat with timeout and flowdroid command
        cmd = self.ic3_cmd + " " + self.file_name + " " + self.output().path + " " + android_path

        # running the command
        # noinspection PyArgumentList
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shellddsdds=True)

        logger.debug('Running IC3 command: ' + cmd)

        # get output, err and status of process
        output, err = process.communicate()
        status = process.returncode


class AggregateFlows(luigi.Task):
    apks = luigi.TupleParameter()
    pkg = luigi.Parameter()

    # requires json of single releases
    def requires(self):
        flowdroid_extra_options = '--contentsources --filesources --urlsources'
        for apk in self.apks:
            yield fl.FlowDroidJson(file_name=apk,
                                   flowdroid_extra_options=flowdroid_extra_options,
                                   flow_json_folder=cfg.flow_json_folder,
                                   flow_run_folder=cfg.flow_run_folder)

    # output is the json file with aggregated info of the app
    def output(self):
        output_file = os.path.join(cfg.flow_aggregated_json_folder,
                                   self.pkg,
                                   self.pkg + ".json")
        return ExternalFileTarget(output_file)

    def csv_file_to_dict(self, filename):
        with open(filename, 'r') as infile:
            reader = csv.reader(infile, delimiter=';')
            dictionary = {rows[0]: rows[1] for rows in reader}
            return dictionary

    # creates the json application file
    def run(self):
        # create app dictionary
        app = {'pkg': self.pkg, 'apks': []}

        # for each release, add json data to app dict
        for i in self.input():
            with open(i.path) as data_file:
                app['apks'].append(json.load(data_file))
        # sort apks list according to version code
        app['apks'] = sorted(app['apks'], key=lambda k: int(k['vercode']))

        for i in self.input():
            i.cleanup()

        with self.output().open('w') as f:
            json.dump(app, f, indent=1)


# Task to create the application json, containing all json of single releases
class AppFlow(luigi.Task):
    apks = luigi.TupleParameter()
    pkg = luigi.Parameter()
    libs_folder = cfg.libradar_app_libs_folder
    apk_info_folder = cfg.info_app_folder
    susimapping = luigi.Parameter()

    # requires json of single releases
    def requires(self):
        info_path = os.path.join(self.apk_info_folder,
                                 self.pkg, self.pkg + ".json")
        libs_path = os.path.join(self.libs_folder, self.pkg, self.pkg + ".json")

        flowdroid_tasks = AggregateFlows(pkg=self.pkg, apks=self.apks)
        return {'flow_tasks': flowdroid_tasks,
                'app_info': ExternalFile(file_name=info_path),
                'libs': ExternalFile(file_name=libs_path)}

    # output is the json file with aggregated info of the app
    def output(self):
        output_file = os.path.join(cfg.flow_appflow_folder,
                                   self.pkg,
                                   self.pkg + ".json")
        return ExternalFileTarget(output_file)

    def csv_file_to_dict(self, filename):
        with open(filename, 'r') as infile:
            reader = csv.reader(infile, delimiter=';')
            dictionary = {rows[0]: rows[1] for rows in reader}
            return dictionary

    # creates the json application file
    def run(self):
        # create app dictionary
        app = {'pkg': self.pkg, 'apks': []}
        libs_fd = self.input()['libs'].open()
        info_fd = self.input()['app_info'].open()
        lp = lib_utils.LibProvider(libs_fd, lib_names=True, unknown_libs=True,
                                   apk_info_fd=info_fd,
                                   unknown_lib_loc=False)
        categories = self.csv_file_to_dict(self.susimapping)
        # for each release, add json data to app dict
        with open(self.input()['flow_tasks'].path) as data_file:
            data = json.load(data_file)
            for apk in data['apks']:
                vercode = apk['vercode']
                ssdict = defaultdict(int)
                for flow in apk['ss']:
                    sink_name = '<' + flow['sink']['name'] + '>'
                    if sink_name in categories.keys():
                        sink_category = categories[sink_name]
                    else:
                        sink_category = sink_name
                        with open("unknown_sinks.txt", "a") as ls:
                            ls.write(sink_name + "\n")
                    sink_location = flow['sink']['loc']
                    sink_location = sink_location.split(".")[0]
                    sink_lib = lp.get_lib(sink_location, vercode, self.pkg)
                    sink_category = sink_category + ":" + sink_lib if sink_lib != "" else sink_category
                    source_name = '<' + flow['source']['name'] + '>'
                    if source_name is not None and source_name in categories.keys():
                        source_category = categories[source_name]
                    elif source_name is None and 'android.content.Intent' in source_name:
                        source_category = "INTENT"
                    else:
                        source_category = source_name
                        with open("unknown_sources.txt", "a") as ls:
                            ls.write(source_name + "\n")
                    source_location = flow['source']['loc']
                    source_location = source_location.split(".")[0]
                    source_lib = lp.get_lib(source_location, vercode)
                    source_category = source_category + ":" + source_lib if source_lib != "" else source_category
                    if not ('NAN' in source_category or 'NAN' in sink_category):
                        sspair = source_category + " - " + sink_category
                        ssdict[sspair] += 1
                apk_mapped = dict()
                apk_mapped['ss'] = ssdict
                apk_mapped['date'] = apk['date']
                apk_mapped['vercode'] = apk['vercode']
                apk_mapped['incomplete'] = 'incomplete' in apk.keys()
                if 'error' in apk.keys():
                    apk_mapped['error'] = True
                apk_mapped['incomplete'] = 'incomplete' in apk.keys()
                app['apks'].append(apk_mapped)
        # sort apks list according to version code
        app['apks'] = sorted(app['apks'], key=lambda k: int(k['vercode']))

        # write json file to system
        with self.output().open('w') as f:
            json.dump(app, f, indent=1)


# Task to create the heatmap matrix
class AppFlowMatrix(luigi.Task):
    apks = luigi.TupleParameter()
    pkg = luigi.Parameter()

    # requires application json
    def requires(self):
        return {'json': AppFlow(pkg=self.pkg, apks=self.apks)}

    # output is the matrix json file
    def output(self):
        output_file = os.path.join(cfg.flow_appflow_matrix_folder,
                                   self.pkg,
                                   self.pkg + ".json")
        return ExternalFileTarget(output_file)

    def get_matrix(self, app):
        """ returns a matrix with source-sink pairs on the y-axis and version on the x-axis """

        # get all source-sink combinations as y-labels
        ylabels = []
        for apk in app['apks']:
            for k, v in apk['ss'].items():
                if k not in ylabels:
                    if ' - LOG' not in k:  # exclude logs from heatmap
                        ylabels.append(k)
        ylabels.sort()

        if len(ylabels) == 0:
            ylabels.append('No flows')

        matrix = numpy.zeros(shape=(len(app['apks']), len(ylabels)))
        xlabels = []

        # err_value is used to color versions for which flowdroid crashed
        err_value = -1

        for i in range(0, len(app['apks'])):
            default_value = 0
            apk = app['apks'][i]
            xlabels.append(apk['vercode'])
            values = []

            # if flowdroid crashed set matrix to error
            if 'error' in apk:
                default_value = err_value

            for el in ylabels:
                if el in apk['ss'].keys():
                    values.append(numpy.log(1 + apk['ss'][el]))
                else:
                    values.append(default_value)
            matrix[i] = values

        return matrix.T, ylabels, xlabels

    # creates the matrix
    def run(self):
        # create app dictionary

        with open(self.input()['json'].path) as data_file:
            app = json.load(data_file)

        # get matrix and row/col labels
        matrix, ylabels, xlabels = self.get_matrix(app)
        data = {'m': matrix.tolist(),
                'yl': ylabels,
                'xl': xlabels}

        # write matrix to json file
        with self.output().open('w') as data_file:
            json.dump(data, data_file)


# Task to create the heatmap matrix
class AppFlowBaseMatrix(luigi.Task):
    apks = luigi.TupleParameter()
    pkg = luigi.Parameter()

    # requires application json
    def requires(self):
        return {'json': AppFlow(pkg=self.pkg, apks=self.apks)}

    # output is the matrix json file
    def output(self):
        output_file = os.path.join(cfg.flow_appflow_base_matrix_folder,
                                   self.pkg,
                                   self.pkg + ".json")
        return ExternalFileTarget(output_file)

    def get_matrix(self, app):
        """ returns a matrix with source-sink pairs on the y-axis
        and version on the x-axis """

        # get all source-sink combinations as y-labels
        ylabels = []
        for apk in app['apks']:
            for k, v in apk['ss'].items():
                if k not in ylabels:
                    if ' - LOG' not in k:  # exclude logs from heatmap
                        ylabels.append(k)
        ylabels.sort()

        if len(ylabels) == 0:
            ylabels.append('No flows')

        matrix = numpy.zeros(shape=(len(app['apks']), len(ylabels)))
        xlabels = []

        # err_value is used to color versions for which flowdroid crashed
        err_value = -1

        for i in range(0, len(app['apks'])):
            default_value = 0
            apk = app['apks'][i]
            xlabels.append(apk['vercode'])
            values = []

            # if flowdroid crashed set matrix to error
            if 'error' in apk:
                default_value = err_value

            for el in ylabels:
                if el in apk['ss'].keys():
                    values.append(apk['ss'][el])
                else:
                    values.append(default_value)
            matrix[i] = values

        return matrix.T, ylabels, xlabels

    # creates the matrix
    def run(self):
        # create app dictionary

        with open(self.input()['json'].path) as data_file:
            app = json.load(data_file)

        # get matrix and row/col labels
        matrix, ylabels, xlabels = self.get_matrix(app)
        data = {'m': matrix.tolist(),
                'yl': ylabels,
                'xl': xlabels}

        # write matrix to json file
        with self.output().open('w') as data_file:
            json.dump(data, data_file)


# Task to create the application json, containing all json of single releases
class AppFlowHeatmap(luigi.Task):
    apks = luigi.TupleParameter()
    pkg = luigi.Parameter()

    # requires application json
    def requires(self):
        appinfo_file = os.path.join(cfg.info_app_folder,
                                    self.pkg,
                                    self.pkg + '.json')

        return {'matrix': AppFlowMatrix(pkg=self.pkg, apks=self.apks),
                'app_info': ExternalFile(file_name=appinfo_file),
                'app_flow': AppFlow(pkg=self.pkg, apks=self.apks)}

    # output is the heatmap
    def output(self):
        output_file = os.path.join(cfg.flow_appflow_heatmap_folder,
                                   self.pkg + ".pdf")
        return ExternalFileTarget(output_file)

    def get_col_colors_versions(self, col_labels, app_info):
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
        return col_colors

    def get_col_colors_incomplete(self, app_flows):
        col_colors = list()
        for apk in app_flows['apks']:
            if apk['incomplete']:
                col_colors.append('red')
            else:
                col_colors.append('white')
        return col_colors

    def get_app_info(self):
        with self.input()['app_info'].open() as data_file:
            return json.load(data_file)

    def get_app_flows(self):
        with self.input()['app_flow'].open() as data_file:
            return json.load(data_file)

    # creates the heatmap of permission use and saves it to a file
    def create_heatmap(self, data, row_labels, col_labels):

        app_info = self.get_app_info()
        app_flow = self.get_app_flows()
        version_colors = self.get_col_colors_versions(col_labels, app_info)
        incomplete_colors = self.get_col_colors_incomplete(app_flow)
        col_colors = pd.DataFrame.from_dict({'versions': version_colors, 'incomplete': incomplete_colors})
        pdata = pd.DataFrame(data, index=row_labels, columns=col_labels)
        pdata.index.name = "dataflow"
        pdata.columns.name = "Versions"
        col_colors.index = pdata.columns

        row_cluster = True if data.shape[0] > 1 else False
        vmax = pdata.values.max()  # use the maximum value inside the matrix as max
        annot = False  # do not display numbers inside heatmap cells
        splot = heatmaps.plot_heatmap(pdata, vmax=vmax, col_colors=col_colors,
                                      row_cluster=row_cluster, annot=annot)

        # create output folder if it does not exist
        if not os.path.exists(os.path.dirname(self.output().path)):
            os.makedirs(os.path.dirname(self.output().path))

        splot.savefig(os.path.abspath(self.output().path), format='pdf')

    # creates the heatmap
    def run(self):
        # read app matrix from json
        with open(self.input()['matrix'].path) as data_file:
            data = json.load(data_file)

        # get matrix and create the heatmap
        matrix = numpy.array(data['m'])
        self.create_heatmap(matrix, data['yl'], data['xl'])


# WrapperTask to analyze with FlowDroid all apks in the apks folder
class InfoFlowAnalysis(luigi.WrapperTask):
    apks_folder = cfg.fake_apks_folder
    apk_list_file = luigi.Parameter(significant=False)

    def get_apps_from_list(self):
        apps = defaultdict(set)
        # noinspection PyTypeChecker
        with open(self.apk_list_file) as fd:
            app_list = [x.strip() for x in fd.readlines()]
        for app in app_list:
            pkg, _, _ = commons().get_apk_data(app)
            apps[pkg].add(commons().strip_file_name(app))
        return apps

    def requires(self):
        apps = self.get_apps_from_list()

        for pkg, apks in apps.items():
            yield AppFlowHeatmap(pkg=pkg, apks=apks)


class ICAnalysis(luigi.WrapperTask):
    apks_folder = luigi.Parameter()
    apk_list_file = luigi.Parameter(significant=False)

    def get_apps_from_list(self):
        apps = defaultdict(set)
        # noinspection PyTypeChecker
        with open(self.apk_list_file) as fd:
            app_list = [x.strip() for x in fd.readlines()]
        for app in app_list:
            app = app.replace('.apk', '')
            pkg, _, _ = commons().get_apk_data(app)
            apps[pkg].add(app)
        return apps

    def requires(self):
        apps = self.get_apps_from_list()

        for pkg, apks in apps.items():
            for apk in apks:
                yield ICRun(file_name=apk)


if __name__ == '__main__':
    luigi.run(main_task_cls=InfoFlowAnalysis)
