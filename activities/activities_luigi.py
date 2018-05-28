# coding=utf-8
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from collections import defaultdict

import luigi.format
import matplotlib

matplotlib.use('Agg')

sys.path.append("..")
from targets import ExternalFileTarget, ApkFile
import cfg
from commons import commons

logger = logging.getLogger('luigi-interface')
OBFUSCATED_TAG = 'obfuscated'
APPCODE_TAG = 'appcode'
OBFUSCATED_ITEM_SIZE = 2
PACKAGE_PREFIX_MIN_SIZE = 8
PACKAGE_PREFIX_MIN_PARTS = 2


class ActivitiesExtractorRun(luigi.Task):
    """ Extracts activities from apk """
    pkg = luigi.Parameter()
    file_name = luigi.Parameter()
    apk_extractor_path = luigi.Parameter(significant=False)

    # requires path of one single application
    def requires(self):
        return ApkFile(file_name=self.file_name)

    # creates the json application file
    # noinspection PyTypeChecker
    def output(self):
        diff_output_file = os.path.join(cfg.activity_diff_folder,
                                        self.pkg,
                                        self.file_name + ".json")
        return ExternalFileTarget(diff_output_file)

    def run(self):
        # get the command line for apktool and run it
        pkg, _, _ = commons().get_apk_data(self.file_name)
        act_diff_tmp_file = os.path.join(tempfile.gettempdir(), 'soot-pkg-{}.json'.format(self.file_name))
        cmd = "{soot} -apkPath {apk} -apkName {pkg} -act -out {output}".format(
            soot=self.apk_extractor_path,
            apk=self.input().path,
            pkg=pkg,
            output=act_diff_tmp_file)
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

        logger.debug('Running ActivitiesExtractor command: ' + cmd)
        output, err = process.communicate()
        output = output.decode('utf-8')
        err = err.decode('utf-8')
        if len(err) > 0:
            logger.debug('pkgExtractor error: <' + err + '>\n' + cmd)
        logger.debug('pkgExtractor out: ' + output)
        if os.path.exists(act_diff_tmp_file):
            with open(act_diff_tmp_file, 'r') as src_f, self.output().open('w') as dest_f:
                dest_f.write(src_f.read())
            os.remove(act_diff_tmp_file)
        else:
            raise RuntimeError('Pkg extractor failed')


class HiddenActivities(luigi.Task):
    pkg = luigi.Parameter()
    apks = luigi.ListParameter(significant=False)

    @staticmethod
    def atoi(text):
        return int(text) if text.isdigit() else text

    def natural_keys(self, text):
        return [self.atoi(c) for c in re.split('(\d+)', text)]

    # noinspection PyTypeChecker
    def requires(self):
        return [ActivitiesExtractorRun(file_name=fn, pkg=self.pkg) for fn in self.apks]

    # noinspection PyTypeChecker
    def output(self):
        output_file = os.path.join(cfg.activity_hidden_folder,
                                   self.pkg,
                                   self.pkg + ".json")
        return ExternalFileTarget(output_file)

    def run(self):
        app = dict()
        for i in self.input():
            with i.open() as act_file:
                apk_info = json.load(act_file)
                _, version, _ = commons().get_apk_data(i.path)
                app[version] = apk_info
            # for each version except the first, verify if there are automatically
            # granted permissions
        res = defaultdict(list)
        res['pkg'] = self.pkg
        app_ver_it = iter(sorted(app.keys(), key=self.natural_keys))
        prev_ver = next(app_ver_it)
        prev_diff = set(app[prev_ver]['diff'])
        prev_act = set(app[prev_ver]['manifest'])
        for ver in app_ver_it:
            activities = set(app[ver]['manifest'])
            diff = set(app[ver]['diff'])
            delta_appeared = list(prev_diff & activities)
            delta_removed = list(diff & prev_act)
            if delta_appeared:
                apk = {'hidden_in': prev_ver, 'appeared_in': ver, 'activities': delta_appeared}
                res['apps'].append(apk)
            if delta_removed:
                apk = {'was_in': prev_ver, 'removed_in': ver, 'activities': delta_removed}
                res['apps'].append(apk)
            prev_diff = diff
            prev_act = activities
            prev_ver = ver

        with self.output().open('w') as f:
            json.dump(res, f, indent=2)


class AllTaskAnalysis(luigi.WrapperTask):
    apks_folder = cfg.apks_folder
    apk_list_file = luigi.Parameter(significant=False)
    r = luigi.Parameter(default="")

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
            if self.r == 'extract':
                for apk in apks:
                    yield ActivitiesExtractorRun(pkg=pkg, file_name=apk)
            elif self.r == 'hidden':
                yield HiddenActivities(pkg=pkg, apks=apks)
            else:
                print('Error: incorrect phase', self.r)


if __name__ == '__main__':
    luigi.run(main_task_cls=AllTaskAnalysis)
