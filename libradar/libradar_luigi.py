# coding=utf-8
import itertools
import json
import logging

import luigi
import matplotlib

matplotlib.use('Agg')
import numpy
import os
import subprocess
import pandas as pd
import sys

sys.path.append("..")
import cfg
import heatmaps
import lib_utils
from collections import defaultdict
from targets import ExternalFileTarget, ApkFile, ExternalFile
from commons import commons

logger = logging.getLogger('luigi-interface')

# TODO move this inside some init method
# load libradar tag_rules
tag_rules = {}
with open('tag_rules_libradar.csv') as f:
    for line in f:
        split = line.strip().split(',')
        tag_rules[split[0]] = split[1]



class LibRadarRun(luigi.Task):
    """ runs libradar on the apk and saves output to txt file """
    file_name = luigi.Parameter()
    libradar_script_cmd = luigi.Parameter()

    def __init__(self, *args, **kwargs):
        super(LibRadarRun, self).__init__(*args, **kwargs)
        self.pkg, self.vercode, self.date = commons().get_apk_data(self.file_name)

    # requires json of single releases
    def requires(self):
        return ApkFile(file_name=self.file_name)

    def output(self):
        output_file = os.path.join(cfg.libradar_run_folder,
                                   self.pkg,
                                   self.file_name + ".txt")
        return ExternalFileTarget(output_file)

    # creates the json application file
    def run(self):
        # in order to use cmd, redis-server must be running
        # redis-server <path_to_libradar>/LibRadar/tool/redis.conf &
        cmd = self.libradar_script_cmd + " " + self.input().path
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

        logger.debug('Running Libradar command: ' + cmd)
        output, err = process.communicate()
        output = output.decode('utf-8')
        err = err.decode('utf-8')
        logger.debug('Libradar error: ' + err)
        logger.debug('Libradar out: ' + output)

        self.input().cleanup()

        if err != '':
            logger.error('Libradar error: ' + err)
            return

        # TODO add check and if libradar failed don't create output file

        # write libradar output to output txt file
        with self.output().open('w') as f:
            f.write(output)


class PkgLibrary(luigi.Task):
    apks = luigi.ListParameter(significant=False)
    pkg = luigi.Parameter()

    # requires json of single releases
    def requires(self):
        return [LibRadarRun(file_name=apk) for apk in self.apks]

    # output is the json file with aggregated info of the app
    def output(self):
        output_file = os.path.join(cfg.libradar_pkglibrary_folder, self.pkg,
                                   self.pkg + ".json")
        return ExternalFileTarget(output_file)

    def run(self):
        pkg_lib = {}
        for i in self.input():
            lib2location = dict()
            library = ""
            with i.open() as lib_file:
                for line in lib_file.readlines():
                    if line.find("Library") >= 0 and library == "":
                        library = line.split(":")[-1][
                                  line.split(":")[-1].index('"') + 1:line.split(":")[-1].rindex('"')]
                    elif line.find("Package") >= 0 and library != "":
                        lib2location[library] = line.split(":")[-1][
                                                line.split(":")[-1].index('L') + 1:line.split(":")[-1].rindex('"')]
                        library = ""
                _, version, _ = commons.get_apk_data(i.path)
                pkg_lib[version] = lib2location

        with self.output().open('w') as f:
            json.dump(pkg_lib, f, sort_keys=True)




class CompareSmali(luigi.Task):
    """ creates an output files with all pkgnames in smalilist file produced by
    apktool script which have not been identified as libraries """
    apks = luigi.TupleParameter()
    pkg = luigi.Parameter()

    smalilist_folder = cfg.soot_smalilist_folder

    def requires(self):
        smalilist_file = os.path.join(self.smalilist_folder,
                                      self.pkg, self.pkg + '.json')
        return {'json': PkgLibrary(pkg=self.pkg, apks=self.apks),
                'smalilist': ExternalFile(file_name=smalilist_file)}

    def output(self):
        output_file = os.path.join(cfg.libradar_comparesmali_folder,
                                   self.pkg, self.pkg + ".json")
        return ExternalFileTarget(output_file)

    def is_pkgname_in_libs(self, libs, smali_pkg):
        smali_pkg = smali_pkg + "."
        reduced_pkg = lib_utils.LibProvider.get_reduced_pkg(self.pkg)
        reduced_pkg = reduced_pkg.replace('/', '.')
        if smali_pkg.startswith(reduced_pkg):
            return True
        for lib, location in libs.items():
            location = location.replace('/', '.') + "."
            if smali_pkg.startswith(location):
                return True
        return False

    def run(self):
        pkg_additional_libs = {}
        with self.input()['smalilist'].open() as f_smali, self.input()['json'].open() as f_libradar:
            pkg_smali = json.load(f_smali)
            pkg_lib = json.load(f_libradar)
            for vercode in set(pkg_smali.keys()) & set(pkg_lib.keys()):
                additional_libs = set()
                smali = pkg_smali[vercode]
                libs = pkg_lib[vercode]
                for pkgname in smali:
                    if not self.is_pkgname_in_libs(libs, pkgname):
                        additional_libs.add(pkgname)
                pkg_additional_libs[vercode] = list(additional_libs)

        with self.output().open('w') as f:
            json.dump(pkg_additional_libs, f, sort_keys=True)




class AppLibs(luigi.Task):
    """ Adds applications we map from the smali pkg folder structure
        to the ones found by libradar """
    apks = luigi.TupleParameter()
    pkg = luigi.Parameter()
    MAX_OBFUSCATION_CHUNK_SIZE = 1

    def requires(self):
        return {'json': PkgLibrary(pkg=self.pkg, apks=self.apks),
                'comparesmali': CompareSmali(pkg=self.pkg, apks=self.apks)}

    # output is the json file with aggregated info of the app
    def output(self):
        output_file = os.path.join(cfg.libradar_app_libs_folder
                                   , self.pkg, self.pkg + ".json")
        return ExternalFileTarget(output_file)

    def process_obfuscated_pkg(self, pkg):
        """removes the obfuscated suffix of a package structure, if there are at
        least 2 element remaining it returns the structure, otherwise it
        returns _OBFUSCATED_"""
        chunks = pkg.split('/')
        prefix = list(itertools.dropwhile(lambda chunk: len(chunk) <= self.MAX_OBFUSCATION_CHUNK_SIZE, reversed(chunks)))
        res = '/'.join(reversed(prefix)) if len(prefix) > 1 or len(prefix) == len(chunks) else '_OBFUSCATED_'
        return res

    def run(self):
        # instantiate app variable
        app = {'libs': {},
               'smali': {}
               }

        # load app libs found by libradar
        with self.input()['json'].open() as data_file:
            libradar_app = json.load(data_file)
            for ver, apk in libradar_app.items():
                app['libs'][ver] = apk

        # load the comparesmali file, and for each package, if it is in the
        # tag_rules file, map it to the corresponding library, otherwise
        # leave it as nlib in the heatmap
        additional_lib_file = self.input()['comparesmali'].path
        additional_lib_data = None
        if os.path.isfile(additional_lib_file):
            with open(additional_lib_file) as data_file:
                additional_lib_data = json.load(data_file)

        not_recognized = set()

        # cycle all versions
        for vercode, additional_libs in additional_lib_data.items():
            # create dictionaries for the version code if missing
            app['smali'][vercode] = []
            if vercode not in app['libs'].keys():
                app['libs'][vercode] = {}

            # for each library in smalilist, check if it has a mapping
            # in tag_rules
            for lib in additional_libs:
                recognized = False

                # cycle all tag_rules keys, if it has a match in tag_rules
                # get the corresponding lib name
                for tag, tag_val in tag_rules.items():
                    if lib.startswith(tag + os.path.sep) or lib == tag:
                        libname = tag_val
                        app['libs'][vercode][libname] = lib
                        recognized = True

                if not recognized:
                    # if the lib is obfuscated, either remove the obfuscated
                    # suffix, or put it in the obfuscated lib
                    libname = self.process_obfuscated_pkg(lib)
                    if libname is not '_OBFUSCATED_':
                        not_recognized.add(lib)

                    # add libname in smali dictionary if not duplicated
                    if libname not in app['smali'][vercode]:
                        app['smali'][vercode].append(libname)

        # print not recognized smali paths to external file
        sorted_not_recognized = sorted(list(not_recognized))
        with open(os.path.join("not_recognized.txt"), 'a') as f_out:
            for item in sorted_not_recognized:
                f_out.write(item + '\n')

        # write output to file
        with self.output().open('w') as f_out:
            json.dump(app, f_out, sort_keys=True)


class LibRadarMatrix(luigi.Task):
    apks = luigi.TupleParameter()
    pkg = luigi.Parameter()
    output_folder = cfg.libradar_matrix_folder

    # requires application json
    def requires(self):
        return {'json': AppLibs(pkg=self.pkg, apks=self.apks)}

    # output is the matrix
    def output(self):
        output_file = os.path.join(self.output_folder,
                                   self.pkg,
                                   self.pkg + ".json")
        return ExternalFileTarget(output_file)

    # returns a matrix with source-sink pairs on the y-axis
    # and version on the x-axis
    def get_matrix(self, app):
        # get all source-sink combinations as y-labels
        ylabels = []
        for apk in app['apks']:
            for data in apk['data'].keys():
                if data not in ylabels:
                    ylabels.append(data)
        ylabels.sort()

        if len(ylabels) == 0:
            ylabels.append("No libs found")

        matrix = numpy.zeros(shape=(len(app['apks']), len(ylabels)))
        xlabels = []

        for i in range(0, len(app['apks'])):
            apk = app['apks'][i]
            xlabels.append(apk['vercode'])
            values = []
            for el in ylabels:
                if el in apk['data'].keys():
                    val = apk['data'][el]  # don't limit values here
                    values.append(val)
                else:
                    values.append(0)
            matrix[i] = values

        return matrix.T, ylabels, xlabels

    # creates the heatmap
    def run(self):
        # create app dictionary

        app = {'pkg': self.pkg, 'apks': []}
        with self.input()['json'].open() as data_file:
            data = json.load(data_file)
            pkg_lib = data['libs']
            smali_lib = data['smali']

            for version, data in pkg_lib.items():
                apk = {}
                apk['vercode'] = version
                apk_data = {}

                # add all found libs
                for lib in data.keys():
                    apk_data[lib] = 2

                # add all smali packages found
                for smali in smali_lib[version]:
                    apk_data[smali] = 1

                apk['data'] = apk_data
                app['apks'].append(apk)

        app['apks'] = sorted(app['apks'], key=lambda k: int(k['vercode']))

        # get matrix and row/col labels
        matrix, ylabels, xlabels = self.get_matrix(app)
        data = {'m': matrix.tolist(),
                'yl': ylabels,
                'xl': xlabels}

        # write matrix to json file
        with self.output().open('w') as data_file:
            json.dump(data, data_file)


class LibRadarHeatmap(luigi.Task):
    apks = luigi.TupleParameter()
    pkg = luigi.Parameter()
    app_info_folder = cfg.info_app_folder

    def get_app_info(self):
        with self.input()['app_info'].open() as data_file:
            return json.load(data_file)

    # requires application json
    def requires(self):
        appinfo_file = os.path.join(self.app_info_folder,
                                    self.pkg,
                                    self.pkg + '.json')
        return {'matrix': LibRadarMatrix(pkg=self.pkg, apks=self.apks),
                'app_info': ExternalFile(file_name=appinfo_file)}

    # output is the heatmap
    def output(self):
        output_file = os.path.join(cfg.libradar_heatmap_folder,
                                   self.pkg + ".pdf")
        return ExternalFileTarget(output_file)

    # creates the heatmap of permission use and saves it to a file
    def create_heatmap(self, data, row_labels, col_labels):

        pdata = pd.DataFrame(data, index=row_labels, columns=col_labels)
        pdata.index.name = "libraries"
        pdata.columns.name = "Versions"

        # TODO put this in all heatmap creation. refactor code
        row_cluster = True if data.shape[0] > 1 else False

        # get app_info from external file
        app_info = self.get_app_info()

        col_colors = heatmaps.get_col_colors(col_labels, app_info)

        vmax = pdata.values.max()
        splot = heatmaps.plot_heatmap(pdata, vmax=vmax,
                                      col_colors=col_colors,
                                      row_cluster=row_cluster,
                                      annot=False)

        if not os.path.exists(os.path.dirname(self.output().path)):
            os.makedirs(os.path.dirname(self.output().path))

        splot.savefig(os.path.abspath(self.output().path), format='pdf')

    # creates the heatmap
    def run(self):
        # read app matrix from json
        with self.input()['matrix'].open() as data_file:
            data = json.load(data_file)

        # get matrix and create the heatmap
        matrix = numpy.array(data['m'])
        self.create_heatmap(matrix, data['yl'], data['xl'])




class ApkLibraryAnalysis(luigi.WrapperTask):
    """ WrapperTask to analyze with FlowDroid all apks in the apks folder """
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
            yield AppLibs(pkg=pkg, apks=apks)
            yield LibRadarHeatmap(pkg=pkg, apks=apks)


if __name__ == '__main__':
    luigi.run(main_task_cls=ApkLibraryAnalysis)
