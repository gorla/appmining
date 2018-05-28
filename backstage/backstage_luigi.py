# coding=utf-8
# TODO PhaseOptions.v().setPhaseOption("jb.tr", "ignore-wrong-staticness:true");
import logging

import luigi
import matplotlib

matplotlib.use('Agg')
import os
import subprocess

# pkg_resources.require("seaborn==0.9.dev.k")  # commented for konstantin's version
# !!! use pip install -e git+git+https://github.com/k-o-n-s-t/seaborn.git@trunk#egg=seaborn --user
# !!! to get custom version of seaborn
# import seaborn as sns
import sys

sys.path.append("..")
import cfg
from collections import defaultdict

from targets import ExternalFileTarget, ApkFile
from commons import commons

logger = logging.getLogger('luigi-interface')


# python luigi_analysis.py InfoFlowAnalysis --local-scheduler

class APKFile(luigi.ExternalTask):
    apk_file = luigi.Parameter()

    def output(self):
        return luigi.LocalTarget(self.apk_file)


class ExternalFile(luigi.ExternalTask):
    apk_file = luigi.Parameter()

    def output(self):
        return luigi.LocalTarget(self.apk_file)


class ApkToolRun(luigi.Task):
    file_name = luigi.Parameter()

    def __init__(self, *args, **kwargs):
        super(ApkToolRun, self).__init__(*args, **kwargs)
        self.pkg, self.vercode, self.date = commons().get_apk_data(self.file_name)

    def output(self):
        output_folder = os.path.join(cfg.apktool_run_folder,
                                     self.pkg,
                                     self.pkg + "_" +
                                     self.vercode + "_" +
                                     self.date + ".out")
        return ExternalFileTarget(output_folder)


class BackstageRun(luigi.Task):
    file_name = luigi.Parameter()

    apks_folder = cfg.apks_folder
    backstage_folder = luigi.Parameter()
    output_folder = cfg.backstage_run_api_folder
    # options
    backstage_ui_param = luigi.Parameter()
    backstage_api_param = luigi.Parameter()

    timeout_cmd = luigi.Parameter()
    backstage_java_cmd = luigi.Parameter()
    android_platform = luigi.Parameter()
    current_dir_path = os.path.dirname(os.path.realpath(__file__))

    backstage_api_folder = os.path.join(cfg.evo_data_folder,
                                        cfg.backstage_run_api_folder)
    backstage_ui_folder = os.path.join(cfg.evo_data_folder,
                                       cfg.backstage_run_ui_folder)
    logs_dir = os.path.join(cfg.evo_data_folder,
                            cfg.backstage_logs_folder)

    def __init__(self, *args, **kwargs):
        super(BackstageRun, self).__init__(*args, **kwargs)
        self.pkg, self.vercode, self.date = commons().get_apk_data(self.file_name)

    @staticmethod
    def escape(s):
        s = s.replace("&", "&amp;")
        s = s.replace("<", "&lt;")
        s = s.replace(">", "&gt;")
        s = s.replace('"', "&quot;")
        return s

    def get_apk_file(self):
        filename = self.pkg + "_" + self.vercode + "_" + self.date + ".apk"
        return os.path.join(self.apks_folder, self.pkg, filename)

    def requires(self):
        return {'apk': ApkFile(file_name=self.file_name),
                'out': ApkToolRun(file_name=self.file_name)}

    def output(self):
        output_file = os.path.join(self.backstage_ui_folder,
                                   self.pkg,
                                   self.pkg + "_" +
                                   self.vercode + "_" +
                                   self.date + ".xml")
        return ExternalFileTarget(output_file)

    def run(self):
        logger.info('Running Backstage on apk ' + self.get_apk_file())
        #        return
        # creating the out dir if it does not exist
        if not os.path.exists(os.path.dirname(self.output().path)):
            os.makedirs(os.path.dirname(self.output().path))

        if not os.path.exists(self.backstage_api_folder):
            os.makedirs(self.backstage_api_folder)
        # preparing the command to run:
        # 1) cd to flowdroid folder
        # -noLang -processMenus -numThreads 1
        # cmd = "{} {} -apk {} {} {} -androidJar {} -uiResultsDir {} -apiResultsDir {}".format(self.timeout_cmd,
        #                                                                                      self.backstage_java_cmd,
        #                                                                                      self.get_apk_file(),
        #                                                                                      self.backstage_ui,
        #                                                                                      self.backstage_api,
        #                                                                                      self.android_platform,
        #                                                                                      self.backstage_ui_res,
        #                                                                                      self.backstage_api_res)
        cmd = "cd {backstage_folder} && {time} {backstage} -apk {apk} {ui_param} {api_param} -logsDir {logs} " \
              "-androidJar {android} -apkToolOutput {apktool} -uiResultsDir {ui_res} " \
              "-apiResultsDir {api_res}".format(backstage_folder=self.backstage_folder,
                                                time=self.timeout_cmd,
                                                backstage=self.backstage_java_cmd,
                                                apk=self.input()['apk'].path,
                                                api_param=self.backstage_api_param,
                                                ui_param=self.backstage_ui_param,
                                                android=self.android_platform,
                                                apktool=self.input()['out'].path,
                                                ui_res=self.backstage_ui_folder,
                                                api_res=self.backstage_api_folder,
                                                logs=self.logs_dir)
        print(cmd)

        # running the command
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

        logger.debug('Running backstage command: ' + cmd)
        output, err = process.communicate()

        # log_file = os.path.join(self.output_folder,
        #                         self.pkg,
        #                         self.pkg + "_" +
        #                         self.vercode + "_" +
        #                         self.date + "_log.txt")
        # with open(log_file, 'a') as ll:
        #     ll.write(output + '\n')
        #     ll.write(err + '\n')

        status = process.returncode
        # if status is 124 a timeout occurred: create output file with TIMEOUT
        # error
        if status == 124:
            with self.output().open('w') as f:
                # write xml with error flag for TIMEOUT
                xml_header = "<?xml version=\"1.0\" ?>"
                open_tags = "<UIResults FileFormatVersion=\"100\">"
                timeout_tag = "<error>TIMEOUT</error>"
                closing_tags = "</UIResults>"
                xml_output = xml_header + \
                             open_tags + timeout_tag + closing_tags
                f.write(xml_output + "\n")
                return


class BackstageAnalysis(luigi.WrapperTask):
    apks_folder = cfg.fake_apks_folder
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
                yield BackstageRun(file_name=apk)

if __name__ == '__main__':
    luigi.run(main_task_cls=BackstageAnalysis)
