# coding=utf-8
import json
import logging
import os
import subprocess
import sys
from collections import defaultdict
from itertools import chain

import luigi
import numpy

sys.path.append("..")
import cfg
from commons import commons
from constants import DANGEROUS_PERM_LIST
from targets import ExternalFileTarget, ApkFile

logger = logging.getLogger('info')

# python luigi_apktool.py ApkStructureAnalysis --local-scheduler
# autopep8 luigi_apktool.py --in-place

# check python version, and only allow lunch with python3
if sys.version_info[0] != 3:
    raise Exception("The script has been developed for Python 3")


class InfoApk(luigi.Task):
    """ saves to a json file apk info, such as activities and version number """

    file_name = luigi.Parameter()
    aapt_badging_cmd = luigi.Parameter()

    # requires path of one single application
    def __init__(self, *args, **kwargs):
        super(InfoApk, self).__init__(*args, **kwargs)
        self.pkg, self.vercode, self.date = commons().get_apk_data(self.file_name)

    # requires path of one single application
    def requires(self):
        return ApkFile(file_name=self.file_name)

    # creates the json application file
    def output(self):
        output_file = os.path.join(cfg.info_apk_folder,
                                   self.pkg,
                                   self.file_name + ".json")
        return ExternalFileTarget(output_file)

    # refactor from permission task
    def set_apk_aapt_data(self, apk):
        # launch aapt dump badging command and parse output
        cmd = self.aapt_badging_cmd + " " + self.input().path
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

        logger.debug('Running aapt command: ' + cmd)
        output, err = process.communicate()
        output = output.decode('utf-8')
        err = err.decode('utf-8')
        logger.debug('aapt error: ' + err)
        logger.debug('aapt out: ' + output)

        apk['perms'] = []

        # get version code and platformBuildVersionName
        # from aapt dump badging output
        if 'package' in output:
            split = output.split('package: ')[1]
            apk['versionName'] = split.split("versionName='")[1] \
                .split("'")[0]

            apk['platformBuildVersionName'] = split.split("platformBuildVersionName='")[1] \
                .split("'")[0]

        # get main activity from aapt dump badging output
        if 'launchable-activity: ' in output:
            split = output.split('launchable-activity: ')[1]
            apk['activity'] = split.split("name='")[1].split("'")[0]

        # get sdkVersion
        if 'sdkVersion:' in output:
            split = output.split("sdkVersion:")[1]
            apk['sdkVersion'] = split.split("'")[1].split("'")[0]

        # get targetSdkVersion
        if 'targetSdkVersion:' in output:
            split = output.split("targetSdkVersion:")[1]
            apk['targetSdkVersion'] = split.split("'")[1].split("'")[0]

        # get all dangerous permissions
        rows = output.split('\n')
        for r in rows:
            if r.startswith('uses-permission: name='):

                # get full permission name
                full_perm = r.split("uses-permission: name='")[1].split("'")[0]

                # filter only android.permission.*
                if full_perm.startswith('android.permission.'):
                    perm = full_perm.split('android.permission.')[1]

                    # only keep  permissions in the dangerous group
                    if perm in DANGEROUS_PERM_LIST:
                        apk['perms'].append(perm)

    # get all apk info and dump them on the json file
    def run(self):
        # creat apk dictionary
        apk = {}

        # get aapt data
        self.set_apk_aapt_data(apk)

        # get op permission data from androguard
        # TODO create another script for this so we don't have soot
        # requirements for this task
        # self.set_androguard_op_permissions(apk)

        # write apk to json file
        with self.output().open('w') as f:
            json.dump(apk, f, sort_keys=True)

        # cleanup file
        self.input().cleanup()


class InfoApp(luigi.Task):
    """  Creates a json with info of all apks """
    apks = luigi.ListParameter(significant=False)
    pkg = luigi.Parameter()

    androguard_api_folder = luigi.Parameter()
    mapping_cash = {}
    min_sdk = 9

    def requires(self):
        infoapks = [InfoApk(file_name=apk) for apk in self.apks]

        return {'infoapk': infoapks}

    def output(self):
        output_file = os.path.join(cfg.info_app_folder,
                                   self.pkg,
                                   self.pkg + '.json')
        return ExternalFileTarget(output_file)

    def get_mapping_path(self, target_sdk):
        dest = os.path.join(self.androguard_api_folder, 'androguard_api' + str(target_sdk) + '.txt')
        if target_sdk < self.min_sdk:
            raise IOError("No androguar mapping found")
        if not os.path.exists(dest):
            logger.warning("No androguar mapping found for sdk " + str(target_sdk) + "; trying to use lower sdk")
            dest = self.get_mapping_path(target_sdk - 1)
        return dest

    def load_mapping(self, target_sdk):
        with open(self.get_mapping_path(target_sdk)) as data_file:
            mapping = json.load(data_file)
        return mapping

    def get_mapping(self, target_sdk):
        if target_sdk not in self.mapping_cash.keys():
            self.mapping_cash[target_sdk] = self.load_mapping(target_sdk)
        return self.mapping_cash[target_sdk]

    def normalise_perm(self, app_perms):
        return set([perm if '.' in perm else 'android.permission.' + perm for perm in app_perms])

    # sets op permissions by looking at API invocation and androguard mappings
    def set_op_perms(self, perm_apis, app, ver):

        target_sdk = int(app[ver].get('targetSdkVersion',
                                      app[ver].get('sdkVersion', 19)))
        target_sdk = max(target_sdk, self.min_sdk)
        # load permission mapping
        mapping = self.get_mapping(target_sdk)

        # remove the additional part in case of ContentResolver apis, which are in form
        # <api>(categories), and keep only until the ">'
        api_set = set([api[:api.index('>') + 1] if api.endswith('}') else api
                       for api in perm_apis[ver].keys()])
        used_perm_apis = api_set & set(mapping.keys())
        used_perms = set(chain.from_iterable(mapping[api] for api in used_perm_apis))

        app_perms = self.normalise_perm(app[ver]['perms'])
        # op_perms = app_perms - used_perm_lib - used_perm_native
        op_perms = app_perms - used_perms

        op_perms_list = [p.replace('android.permission.', '') for p in op_perms]
        app[ver]['op_perms'] = op_perms_list

    def run(self):

        app = {}

        # for each apk, add info_apk to app[ver] dictionary
        for i in self.input()['infoapk']:
            with i.open() as info_file:
                apk_info = json.load(info_file)
                _, version, _ = commons().get_apk_data(i.path)
                app[version] = apk_info

        with self.output().open('w') as f:
            json.dump(app, f, sort_keys=True, indent=2)


class PermissionMatrix(luigi.Task):
    apks = luigi.TupleParameter()
    pkg = luigi.Parameter()
    output_folder = cfg.info_permission_matrix_folder

    # requires application json
    def requires(self):
        return {'json': InfoApp(pkg=self.pkg, apks=self.apks)}

    # outputs the permission matrix json
    def output(self):
        output_file = os.path.join(self.output_folder,
                                   self.pkg,
                                   self.pkg + ".json")
        return luigi.LocalTarget(output_file)

    # returns the permission matrix
    def get_matrix(self, app):
        # get all permissions as y-labels
        ylabels = []
        for apk in app['apks']:
            for data in apk['perms']:
                if data not in ylabels:
                    ylabels.append(data)
        ylabels.sort()

        if len(ylabels) == 0:
            ylabels.append("No permissions asked")

        matrix = numpy.zeros(shape=(len(app['apks']), len(ylabels)))
        xlabels = []

        for i in range(0, len(app['apks'])):
            apk = app['apks'][i]
            xlabels.append(apk['vercode'])
            values = []
            for el in ylabels:
                if el in apk['perms']:
                    values.append(1)
                else:
                    values.append(0)
            matrix[i] = values

        return matrix.T, ylabels, xlabels

    def run(self):
        app = {'pkg': self.pkg, 'apks': []}

        with self.input()['json'].open() as data_file:
            info_app = json.load(data_file)
            for ver, info in info_app.items():
                apk = {}
                apk['vercode'] = ver
                apk['perms'] = info['perms']
                app['apks'].append(apk)

        app['apks'] = sorted(app['apks'], key=lambda k: int(k['vercode']))

        matrix, ylabels, xlabels = self.get_matrix(app)
        data = {'m': matrix.tolist(),
                'yl': ylabels,
                'xl': xlabels}

        # write matrix to json file
        with self.output().open('w') as data_file:
            json.dump(data, data_file)


# WrapperTask to trigger task to extract info from apks
class InfoApkAnalysis(luigi.WrapperTask):
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
            yield InfoApp(pkg=pkg, apks=apks)


if __name__ == '__main__':
    luigi.run(main_task_cls=InfoApkAnalysis)
