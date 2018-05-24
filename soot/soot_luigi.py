# coding=utf-8
import gzip
import itertools
import json
import logging
import os
import subprocess
import sys
import tempfile
from collections import defaultdict

import matplotlib

matplotlib.use('Agg')
import luigi
import luigi.format

sys.path.append("..")
from constants import CONTENT_RESOLVER_API_LIST, AG_API_DICT
from targets import ExternalFileTarget, ApkFile
import flowdroid_dispatcher as fl
import cfg
from commons import commons

logger = logging.getLogger('soot')


class PkgExtractorRun(luigi.Task):
    """
        this task extracts package names from apk with help of soot
        dependencies: apk file
    """
    pkg = luigi.Parameter()
    file_name = luigi.Parameter()
    apk_extractor_path = luigi.Parameter(significant=False)

    # requires path of one single application
    def requires(self):
        return ApkFile(file_name=self.file_name)

    # creates the json application file
    def output(self):
        pkg_output_file = os.path.join(cfg.soot_pkglist_folder,
                                       self.pkg,
                                       self.file_name + ".json")

        return ExternalFileTarget(pkg_output_file)

    def run(self):
        # get the command line for apktool and run it
        pkg, _, _ = commons().get_apk_data(self.file_name)
        pkg_list_tmp_file = os.path.join(tempfile.gettempdir(), 'soot-pkg-{}.json'.format(self.file_name))
        cmd = "{soot} -apkPath {apk} -apkName {pkg} -pkg -packages {pkg_list}".format(
            soot=self.apk_extractor_path,
            apk=self.input().path,
            pkg=pkg,
            pkg_list=pkg_list_tmp_file)
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

        logger.debug('Running pkgExtractor command: ' + cmd)
        output, err = process.communicate()
        output = output.decode('utf-8')
        err = err.decode('utf-8')
        if len(err) > 0:
            logger.debug('pkgExtractor error: <' + err + '>\n' + cmd)
        logger.debug('pkgExtractor out: ' + output)
        if os.path.exists(pkg_list_tmp_file):
            with open(pkg_list_tmp_file, 'r') as src_f, self.output().open('w') as dest_f:
                dest_f.write(src_f.read())
        else:
            raise RuntimeError('Pkg extractor failed')


class ApiExtractorRun(luigi.Task):
    """
        this task extracts api calls from apk with help of soot as; result is a gzip file
        (as side effect it also extracts package list)
        dependencies: apk file
    """
    pkg = luigi.Parameter()
    file_name = luigi.Parameter()
    apk_extractor_path = luigi.Parameter(significant=False)

    # requires path of one single application
    def requires(self):
        return ApkFile(file_name=self.file_name)

    # creates the json application file
    def output(self):
        output_file = os.path.join(cfg.soot_run_folder,
                                   self.pkg,
                                   self.file_name + ".json.gz")
        pkg_output_file = os.path.join(cfg.soot_pkglist_folder,
                                       self.pkg,
                                       self.file_name + ".json")

        return {'api': ExternalFileTarget(output_file, format=luigi.format.Nop),
                'loc': ExternalFileTarget(pkg_output_file)}

    def run(self):
        # get the command line for apktool and run it
        pkg, _, _ = commons().get_apk_data(self.file_name)
        pkg_list_tmp_file = os.path.join(tempfile.gettempdir(), 'soot-pkg-{}.json'.format(self.file_name))
        res_tmp_file = os.path.join(tempfile.gettempdir(), 'soot-tmp-{}.json.gzip'.format(self.file_name))
        cmd = "{soot} -api -pkg -apkPath {apk} -apkName {pkg} -out {out} -packages {pkg_list}".format(
            soot=self.apk_extractor_path,
            apk=self.input().path,
            pkg=pkg,
            out=res_tmp_file,
            pkg_list=pkg_list_tmp_file)
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

        logger.debug('Running apiExtractor command: ' + cmd)
        output, err = process.communicate()
        output = output.decode('utf-8')
        err = err.decode('utf-8')
        if len(err) > 0:
            logger.error('apiExtractor error: <' + err + '>\n' + cmd)
        logger.debug('apiExtractor out: ' + output)
        if os.path.exists(res_tmp_file):
            with open(res_tmp_file, 'rb') as src_f, self.output()['api'].open('w') as dest_f:
                dest_f.write(src_f.read())
        else:
            raise RuntimeError('Api extractor failed')
        if os.path.exists(pkg_list_tmp_file):
            with open(pkg_list_tmp_file, 'r') as src_f, self.output()['loc'].open('w') as dest_f:
                dest_f.write(src_f.read())


class ExtractPermissionApi(luigi.Task):
    """
        extracts APIs covered by dangerous permissions (the list is based on Androguard mapping)
    """
    file_name = luigi.Parameter()
    pkg = luigi.Parameter()

    def requires(self):
        return ApiExtractorRun(file_name=self.file_name, pkg=self.pkg)

    def output(self):
        output_file = os.path.join(cfg.soot_permission_api_folder,
                                   self.pkg,
                                   self.file_name + ".json")
        return ExternalFileTarget(output_file)  # , format=luigi.format.Gzip)

    def run(self):
        # pkg, vercode, date = commons().get_apk_data(self.file_name)
        with self.input()['api'].open() as fd:  # it's a gzip file
            fin = gzip.GzipFile(fileobj=fd)
            json_bytes = fin.read()
            json_str = json_bytes.decode('utf-8')
            apis = json.loads(json_str)

        perm_apis = {}

        # filter only APIs present in permission mappings
        for api, loc in apis.items():
            if api in AG_API_DICT:
                perm_apis[api] = loc

        with self.output().open('w') as f:
            json.dump(perm_apis, f, indent=2)


class SmaliList(luigi.Task):
    pkg = luigi.Parameter()
    apks = luigi.ListParameter(significant=False)

    def requires(self):
        return [ApiExtractorRun(file_name=fn, pkg=self.pkg) for fn in self.apks]

    def output(self):
        output_file = os.path.join(cfg.soot_smalilist_folder,
                                   self.pkg,
                                   self.pkg + ".json")
        return ExternalFileTarget(output_file)

    def run(self):
        app_smalilist = {}

        for i in self.input():
            with i['loc'].open() as data_file:
                _, ver, _ = commons().get_apk_data(i['loc'].path)
                smali = json.load(data_file)

                # cast to set to remove duplicates
                app_smalilist[ver] = list(set(smali))

        with self.output().open('w') as data_file:
            json.dump(app_smalilist, data_file, indent=2)


class Combiner(luigi.Task):
    pkg = luigi.Parameter()
    apks = luigi.ListParameter(significant=False)

    def requires(self):
        return {'fl': fl.FlowDroidContentRes(pkg=self.pkg, apks=self.apks),
                'api': [ExtractPermissionApi(file_name=fn, pkg=self.pkg) for fn in self.apks]}

    def output(self):
        output_file = os.path.join(cfg.soot_combined_folder,
                                   self.pkg,
                                   self.pkg + ".json")
        return ExternalFileTarget(output_file)

    @staticmethod
    def normalize_location(content_loc, raw_loc):
        res = []
        for loc in content_loc:
            term_loc = loc + '.'
            item = loc
            for l in raw_loc:
                if term_loc.startswith(l + '.'):
                    item = l
                    break
            res.append(item)
        return res

    @staticmethod
    def merge_apis(apis, content_res):
        apis_locations = set((itertools.chain(*apis.values())))
        for cr in content_res:
            cr_api = cr.split('{')[0]
            try:
                content_res[cr] = Combiner.normalize_location(content_res[cr], apis_locations)
                loc = set(apis[cr_api]) - set(content_res[cr])
                apis[cr_api] = list(loc) if len(loc) > 0 else None
                apis[cr] = content_res[cr]
            except:
                pass
        return apis

    def run(self):
        with self.input()['fl'].open() as fl_file:
            content_res = json.load(fl_file)
        target_apis = dict()
        for i in self.input()['api']:
            with i.open() as data_file:
                _, ver, _ = commons().get_apk_data(i.path)
                raw_apis = json.load(data_file)
                apis = self.merge_apis(raw_apis, content_res[ver]) if ver in content_res else raw_apis
                # add {} for unresolved ContentRes
                for api in apis:
                    if api in CONTENT_RESOLVER_API_LIST:
                        apis[api + '{}'] = apis[api]
                        del apis[api]
                target_apis[ver] = apis

        # check all apis: if they belong to content resolver list ensure
        # that they have the content resolver categories in curly braces
        # following the api (<api>{content resolver categories}). If they
        # don't, add empty curly braces at the end and remove old api
        # from the dictionary
        with self.output().open('w') as f:
            json.dump(target_apis, f, indent=2)


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
            pkg, _, _ = commons().get_apk_data(app)
            apps[pkg].add(commons().strip_file_name(app))
        return apps

    def requires(self):
        apps = self.get_apps_from_list()
        for pkg, apks in apps.items():
            if self.r == 'run':
                for apk in apks:
                    yield ApiExtractorRun(pkg=pkg, file_name=apk)
            if self.r == 'pkg':
                for apk in apks:
                    yield PkgExtractorRun(pkg=pkg, file_name=apk)
            elif self.r == 'api':
                for apk in apks:
                    yield ExtractPermissionApi(pkg=pkg, file_name=apk)
            elif self.r == 'combine':
                yield Combiner(pkg=pkg, apks=apks)
            elif self.r == 'smalilist':
                yield SmaliList(pkg=pkg, apks=apks)

            else:
                print('Error: incorrect phase', self.r)


if __name__ == '__main__':
    luigi.run(main_task_cls=AllTaskAnalysis)
