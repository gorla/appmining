import itertools
import json
import logging
import os
import re
import subprocess
import sys
from collections import defaultdict

import luigi
from functional import seq  # pip install pyfunctional

sys.path.append("..")
import flowdroid_dispatcher as fl
from targets import ExternalFileTarget, ApkFile, ExternalFile
from constants import DANGEROUS_GROUPS, DANGEROUS_GROUPS_MAPPING, DANGEROUS_PERM_LIST, CONTENT_RESOLVER_PERMS, AG_MAPPING, AG_API_DICT, \
    AG_API_MAPPINGS_FOLDER

import cfg
import lib_utils
import utils.utils as utils
from commons import commons

# TODO move apk_parse code into info_apk directory
sys.path.insert(0, '../dynamic_analysis/apk_parse')

# import androguard
sys.path.insert(0, './androguard_repo')
import androguard.misc

# check python version, and only allow lunch with python3
if sys.version_info[0] != 3:
    raise Exception("The script has been developed for Python 3")


class PermissionApk(luigi.Task):
    logger = logging.getLogger('permissions')
    file_name = luigi.Parameter()
    aapt_badging_cmd = luigi.Parameter()

    # requires path of one single application
    def __init__(self, *args, **kwargs):
        super(PermissionApk, self).__init__(*args, **kwargs)
        self.pkg, self.vercode, self.date = commons().get_apk_data(self.file_name)

    def requires(self):
        return ApkFile(file_name=self.file_name)

    # creates the json application file
    def output(self):
        output_file = os.path.join(cfg.permission_apk_folder,
                                   self.pkg,
                                   self.file_name + ".json")
        return ExternalFileTarget(output_file)

    @staticmethod
    def with_attributes(line):
        return ' ' in line

    def parse_aapt_output(self, output):
        attributes = {'platformBuildVersionName', 'versionName', 'sdkVersion', 'launchable-activity',
                      'targetSdkVersion', 'uses-permission'}
        attr_map = {'uses-permission': 'perms', 'launchable-activity': 'activity'}
        list_attrs = {'uses-permission'}
        info_dict = dict()
        pairs = []
        # collect key-value pairs from aapt output
        for line in output.split('\n'):
            if self.with_attributes(line):
                name, attrs = line.split(':', 1)
                name = name.strip(" '")
                kv = seq(attrs.split(' ')) \
                    .filter(lambda x: '=' in x) \
                    .map(lambda x: x.split('=')) \
                    .map(lambda x: (name if x[0] == 'name' else x[0], x[1]))
                pairs.extend(kv)
            else:
                pairs.append(tuple(line.split(':')))
        # filter out unnecessary attributes

        pairs = seq(pairs) \
            .filter(lambda x: x[0] in attributes) \
            .map(lambda x: (x[0], x[1].strip(" '").replace('android.permission.', ''))) \
            .filter(
            lambda x: ('uses-permission' != x[0]) ^ (  # collect all attrs plus dangerous perms
                    x[1] in DANGEROUS_PERM_LIST))  # ~> 'uses-permission' == key and value in DANGEROUS_PERM_LIST))
        # add attributes which should be a list
        for attr in list_attrs:
            key = attr_map.get(attr, attr)
            info_dict[key] = list(seq(pairs).filter(lambda x: attr == x[0]).map(lambda x: x[1].strip("'")))
        # add other attrsq
        for attr, value in filter(lambda x: x[0] not in list_attrs, pairs):
            key = attr_map.get(attr, attr)
            info_dict[key] = value

        # append empty attributes
        mapped_attrs = attributes.union(attr_map.values()).difference(attr_map.keys())
        for attr in mapped_attrs - info_dict.keys():
            info_dict[key] = ''
        return info_dict

    def set_apk_aapt_data(self):
        # launch aapt dump badging command and parse output
        cmd = "{apt} {apk}".format(apt=self.aapt_badging_cmd, apk=self.input().path)
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

        self.logger.debug('Running aapt command: ' + cmd)
        output, err = process.communicate()
        output = output.decode('utf-8')
        err = err.decode('utf-8')
        # self.input().cleanup()
        if process.returncode != 0:
            self.logger.error('aapt error: {}'.format(err))
            return None
        self.logger.debug('aapt out: {}'.format(output))
        return self.parse_aapt_output(output)

    def run(self):
        apk = self.set_apk_aapt_data()
        if apk is None:
            return
        apk['file'] = self.file_name

        # write apk to output file
        with self.output().open('w') as f:
            json.dump(apk, f, sort_keys=True, indent=2)


class PermissionApp(luigi.Task):
    """ Creates a json with info of all apks """
    apks = luigi.ListParameter(significant=False)
    pkg = luigi.Parameter()

    def requires(self):
        # noinspection PyTypeChecker
        return [PermissionApk(file_name=apk) for apk in self.apks]

    def output(self):
        # noinspection PyTypeChecker
        output_file = os.path.join(cfg.permission_app_folder,
                                   self.pkg,
                                   self.pkg + '.json')
        return ExternalFileTarget(output_file)

    @staticmethod
    def atoi(text):
        return int(text) if text.isdigit() else text

    def natural_keys(self, text):
        return [self.atoi(c) for c in re.split('(\d+)', text)]

    @staticmethod
    def get_perm_group(perm):
        return DANGEROUS_GROUPS_MAPPING.get(perm, "NOT_DANGEROUS")

    # returns the list of automatically granted permissions
    # input are sets
    def get_automatically_granted_perms(self, curr_ver_perms, last_ver_perms):
        auto_granted_perms = set()
        # if permission was already requested in last version, skip it
        actual_perm_set = curr_ver_perms - last_ver_perms
        actual_perm_set = actual_perm_set & DANGEROUS_GROUPS_MAPPING.keys()
        for perm in actual_perm_set:
            # retrieve permission group
            group = self.get_perm_group(perm)

            # check if other permissions in the same group were requested
            dangerous_group = DANGEROUS_GROUPS[group]
            is_last_granted = len(dangerous_group & last_ver_perms) > 0
            # if another permission in the group was granted in both
            # previous and current version, it is automatically granted
            if is_last_granted:
                auto_granted_perms.add(perm)
                #     # if another permission in the group was granted in both
                #     # previous and current version, it is automatically granted
                #     if p in curr_ver_perms and p in last_ver_perms:

        return auto_granted_perms

    def run(self):
        app = {}

        # for each apk, add info_apk to app[ver] dictionary
        for i in self.input():
            with i.open() as info_file:
                apk_info = json.load(info_file)
                pkg, version, date = commons().get_apk_data(i.path)
                # apk_info['file_name'] = commons.get_apk_name(pkg, version, date)
                app[version] = apk_info

        # for each version except the first, verify if there are automatically
        # granted permissions
        app_ver_it = iter(sorted(app.keys(), key=self.natural_keys))  # .sort(key=self.natural_keys)??
        perms = app[next(app_ver_it)]['perms']
        if type(perms) != list:  # temporary workaround to process legacy data
            perms = [perms]  # redundant for new data
        last_ver_perms = set(perms)
        last_autogranted_perms = set()
        for ver in app_ver_it:
            apk_info = app[ver]
            # if we have found another apk with targetSdkVersion > 23,
            # get the list of permissions declared in latest version
            # before the current one and extract automatically granted ones
            if type(apk_info['perms']) != list:  # temporary workaround to process legacy data
                apk_info['perms'] = [apk_info['perms']]  # redundant for new data
            current_ver_perms = set(apk_info['perms'])
            target_sdk = apk_info.get('targetSdkVersion', 0)
            if type(target_sdk) == list:
                print(target_sdk)
            if not target_sdk:
                target_sdk = apk_info.get('sdkVersion', 0)
            if int(target_sdk) >= 23:
                auto_granted = self.get_automatically_granted_perms(current_ver_perms,
                                                                    last_ver_perms)
                # if a permission was autogranted in last version and is still
                # in the permission list, we consider it as autogranted
                auto_granted = (current_ver_perms & last_autogranted_perms) | auto_granted

                if auto_granted:
                    app[ver]['auto_granted'] = list(auto_granted)
                last_autogranted_perms = auto_granted
            last_ver_perms = current_ver_perms

            # get the list of versions, sorted numerically
        # versions = app.keys()
        # versions.sort(key=self.natural_keys)

        with self.output().open('w') as f:
            json.dump(app, f, sort_keys=True, indent=2)


class AndroguardApiLocation(luigi.Task):
    """ takes the list of apktool api location, and filters out all
    apis that don't belong to a dangerous permission of the
    androguard api mappings. Then all locations are substituted
    with the corresponding library name """
    apks = luigi.TupleParameter(significant=False)
    pkg = luigi.Parameter()

    # noinspection PyTypeChecker
    def requires(self):
        permapp = PermissionApp(pkg=self.pkg, apks=self.apks)
        api_loc = os.path.join(cfg.soot_combined_folder,
                               self.pkg, self.pkg + ".json")
        info_path = os.path.join(cfg.info_app_folder,
                                 self.pkg, self.pkg + ".json")
        libs_path = os.path.join(cfg.libradar_app_libs_folder,
                                 self.pkg, self.pkg + ".json")

        return {'permapp': permapp,
                'api_loc': ExternalFile(file_name=api_loc),
                'info_path': ExternalFile(file_name=info_path),
                'libs_path': ExternalFile(file_name=libs_path)}

    # noinspection PyTypeChecker
    def output(self):
        output_file = os.path.join(cfg.permission_androguard_api_loc_folder,
                                   self.pkg,
                                   self.pkg + ".json")
        return ExternalFileTarget(output_file)

    # removes the obfuscated part of a package structure, if there are at
    # least 2 element remaining it returns the structure, otherwise it
    # returns _OBFUSCATED_
    @staticmethod
    def process_obfuscated_pkg(loc):
        if loc == 'appcode' or loc == 'appcode/':
            return 'appcode'

        if loc == '.':
            return '_OBFUSCATED_'

        split = loc.split('.')

        cut = len(split)
        for s in reversed(split):
            if len(s) > 1:
                break
            else:
                cut -= 1

        # if pkg path was cut and only has length of one
        if cut > 1 or cut == len(split):
            return '.'.join(split[0:cut])
        else:
            return '_OBFUSCATED_'

    def run(self):
        # load lib provider
        libs_fd = self.input()['libs_path'].open()
        info_fd = self.input()['info_path'].open()
        lib_provider = lib_utils.LibProvider(libs_fd,
                                             lib_names=True,
                                             unknown_libs=False,
                                             apk_info_fd=info_fd,
                                             unknown_lib_loc=True)

        # load app info from external file
        # with self.input()['permapp'].open() as data_file:
        #     perm_app = json.load(data_file)

        # load api with location from external file
        with self.input()['api_loc'].open() as data_file:
            apktool_api = json.load(data_file)

        # only keep the dangerous permission related apis
        api_loc_dict = {}
        for ver, api_dict in apktool_api.items():
            api_loc_dict[ver] = {}
            for api, locs in api_dict.items():
                # use base api for the comparison
                # (removing content resolver categories)
                base_api = api[:api.index('>') + 1] if utils.is_cr_api(api) else api

                # skip the api if it is not in the androguard dict
                if base_api not in AG_API_DICT:
                    continue

                # use lib_provider to get the library name or
                # reduced pkg version of the location
                locations = set()
                for loc in locs:

                    # get library name from location
                    lib = lib_provider.get_lib(loc, ver, self.pkg)
                    # if the library is not recognized we keep the original loc
                    if lib == "":
                        lib = loc
                        # commented lib_utils code, we keep the loc which is
                        # found by soot/apktool (which is already redyced)
                        # lib = lib_utils.LibProvider.get_fully_reduced_pkg(loc)
                    lib = self.process_obfuscated_pkg(lib)

                    # add location to the set
                    locations.add(lib)

                # add api with location list to the dictionary
                api_loc_dict[ver][api] = sorted(locations)

        with self.output().open('w') as f:
            json.dump(api_loc_dict, f, sort_keys=True)


class AutoGrantedApi(luigi.Task):
    """ gets the list of api calls for each automatically granted
    permission, filtering the list of api calls extracted with
    androzoo with using the mappings provided by androguard
    """
    apks = luigi.TupleParameter(significant=False)
    pkg = luigi.Parameter()

    def __init__(self, *args, **kwargs):
        super(AutoGrantedApi, self).__init__(*args, **kwargs)
        self.lib_app = {}
        self.all_versions = []

    # noinspection PyTypeChecker
    def requires(self):
        permapp = PermissionApp(pkg=self.pkg, apks=self.apks)
        info_path = os.path.join(cfg.info_app_folder,
                                 self.pkg, self.pkg + ".json")
        libs_path = os.path.join(cfg.libradar_app_libs_folder,
                                 self.pkg, self.pkg + ".json")

        return {'permapp': permapp,
                'info_path': ExternalFile(file_name=info_path),
                'libs_path': ExternalFile(file_name=libs_path),
                'ag_api_loc': AndroguardApiLocation(apks=self.apks, pkg=self.pkg)}

    # noinspection PyTypeChecker
    def output(self):
        output_file = os.path.join(cfg.permission_autogranted_api_folder,
                                   self.pkg,
                                   self.pkg + '.json')
        return ExternalFileTarget(output_file)

    # returns the version previous to the input one
    def prev_version(self, ver):
        index = self.all_versions.index(ver)
        if index > 0:
            return self.all_versions[index - 1]
        else:
            return None

    # returns true if the library was used in the previous version,
    # checking both libraries found by libradar and smali code
    def lib_used_in_prev_version(self, lib, prev_ver, lib_provider):
        # return False if lib is appcode, obfuscated, or previous
        # version is None
        if (lib is 'appcode' or prev_ver is None or
                lib is '_OBFUSCATED_'):
            return False

        # return True if lib was in last versions's libraries or
        # lib was in last versions's smali code
        if (lib in lib_provider.libs_dict[prev_ver].values() or
                lib in self.lib_app['smali'][prev_ver]):
            return True

        # else return False
        return False

    # returns true if the input permission is required for api call.
    # we check if the api contains content resolver categories (inputted in the
    # format <api>{cat1, cat2, etc} - comma separated and in curly braces):
    # if it does, we check if the permission is required by one of the categories,
    # otherwise we check if the api is included in the list of androguard apis
    @staticmethod
    def is_perm_required_for_api(perm, api, ag_perm_apis):

        # if there are ContentResolver categories, check if perm
        # is required by one of them
        if utils.is_cr_api(api):

            # if the api contains no categories return False
            if api.endswith('{}'):
                return False

            if perm in utils.get_perm_from_api_categories(api):
                return True

        # else check if the api is in the androguard mappings for the perm
        else:
            if api in ag_perm_apis:
                return True

        return False

    # returns all apis extracted with apktool that match input perm
    # according to androguard mappings
    def get_target_apis(self, api_loc_apk, perm, ver, lib_provider):
        # read androguard mappings for the input permission
        mapping_fp = os.path.join(AG_API_MAPPINGS_FOLDER,
                                  perm + '.txt')
        ag_perm_apis = [line.rstrip('\r\n') for line in open(mapping_fp)]

        # cycle all apis extracted for the input apk, if they are present
        # in androguard mappings, add them to return list, also saving
        # info regarding where api is called (application or library)
        target_apis = {}

        # for each api, if it is in the androguard mapping, add
        # it to the return array for each location it was found in
        for api, locs in api_loc_apk.items():

            if self.is_perm_required_for_api(perm, api, ag_perm_apis):
                base_api = api[:api.index('>') + 1] if utils.is_cr_api(api) else api
                api_locs = set()
                for lib in locs:
                    prev_ver = self.prev_version(ver)

                    # add the api with corresponding library or location
                    # to the return array. if library was available also in
                    # the previous version, add a '+' to the end
                    if self.lib_used_in_prev_version(lib, prev_ver,
                                                     lib_provider):
                        api_locs.add(lib + '+')
                    else:
                        api_locs.add(lib)
                target_apis[base_api] = list(api_locs)

        return target_apis

    def run(self):
        # create app dictionary
        app = {}

        # load lib app file
        with self.input()['libs_path'].open() as data_file:
            self.lib_app = json.load(data_file)

        # load lib provider
        libs_fd = self.input()['libs_path'].open()
        info_fd = self.input()['info_path'].open()
        lp = lib_utils.LibProvider(libs_fd,
                                   lib_names=True,
                                   unknown_libs=True,
                                   apk_info_fd=info_fd,
                                   unknown_lib_loc=True)
        # load app info from external file
        with self.input()['permapp'].open() as data_file:
            perm_app = json.load(data_file)

        # write the sorted list of versions in a class variable
        self.all_versions = list(perm_app.keys())
        self.all_versions.sort(key=int)

        with self.input()['ag_api_loc'].open() as data_file:
            api_loc_app = json.load(data_file)

        # for each version, if it has automatically granted perms,
        # get the apktool api list and filter them according to
        # androguard permission list
        for ver, apk_info in perm_app.items():
            if 'auto_granted' in apk_info.keys():
                app[ver] = {}

                # for each automatically granted permission, get the list
                # of apis (with location) that require that permission
                for perm in apk_info['auto_granted']:
                    app[ver][perm] = self.get_target_apis(api_loc_app[ver],
                                                          perm, ver, lp)

        # write output to file
        with self.output().open('w') as f:
            json.dump(app, f, sort_keys=True, indent=2)


class MakeSourcesSinks(luigi.Task):
    file_name = luigi.Parameter()
    permissions = luigi.ListParameter()
    src_and_sink_mapping = luigi.Parameter()
    perm_mapping = luigi.Parameter()

    def __init__(self, *args, **kwargs):
        super(MakeSourcesSinks, self).__init__(*args, **kwargs)
        self.pkg, self.vercode, self.date = commons().get_apk_data(self.file_name)
        self.original_sources = []
        self.original_sinks = []
        # noinspection PyTypeChecker
        with open(self.src_and_sink_mapping, "r") as data_file:
            for s in data_file.read().splitlines():
                if "->" not in s or not s.startswith('<'):
                    continue
                api, stype = seq(s.split("->")).map(lambda x: x.strip())
                if stype == '_SOURCE_':
                    self.original_sources.append(api)
                elif stype == '_SINK_':
                    self.original_sinks.append(api)
        self.api_dict = defaultdict(set)
        with open(self.perm_mapping, "r") as fd:
            for line in fd.readlines():
                api, perm = line.strip('\n').split(';')
                if api in self.original_sources:
                    self.api_dict[perm].add(api)

    def output(self):
        output_file = os.path.join(cfg.permission_flowdroid_src_sink_folder,
                                   self.pkg,
                                   self.file_name + ".txt")
        return ExternalFileTarget(output_file)

    # returns true if one of the permissions in the input list
    # can require content resolver to access sensitive data
    @staticmethod
    def require_content_resolver(perm_list):
        return len(CONTENT_RESOLVER_PERMS.intersection(perm_list)) > 0

    # returns the source and sink mapping filtering out all the ones not
    # related to the automatically granted permissions. returns None if
    # source list is empty
    @staticmethod
    def make_source_string(api):
        return "{api} -> _SOURCE_".format(api=api)

    @staticmethod
    def make_sink_string(api):
        return "{api} -> _SINK_".format(api=api)

    def get_ss_mapping(self, permissions):
        # create set for mapping filtered with only auto granted perms
        src_mapping = set()

        for perm in permissions:
            # if the permission is access coarse or fine location, we
            # remap it to ACCESS_LOCATION, as that's how it is listed
            # in the mappings
            if perm == 'ACCESS_COARSE_LOCATION' or perm == 'ACCESS_FINE_LOCATION':
                perm = 'ACCESS_LOCATION'

            # extract all APIs from permission_mapping.txt which correspond
            # to an automatically granted permission
            # for each API, get the corresponding source from SourceAndSink.txt
            src_mapping.update(self.api_dict[perm])

        # if there are automatically granted permissions who can get data
        # from the content resolver, add the content resolver APIS to sources
        with_content_res = self.require_content_resolver(permissions)
        # source and sink mapping is the union of original sinks and
        # of srcs whose API invocation require auto-granted permissions
        ss_mapping = []
        if len(src_mapping) > 0 or with_content_res:
            sinks = map(lambda s: self.make_sink_string(s), self.original_sinks)
            ss_mapping.extend(sinks)
            sources = map(lambda s: self.make_source_string(s), src_mapping)
            ss_mapping.extend(sources)
        return {'ss_mapping': ss_mapping, 'with_content_res': with_content_res}

    def run(self):
        # if there are automatically granted permission, get all input data
        # and use them to set flowdroid src and sinks
        # noinspection PyTypeChecker
        ss_mapping = self.get_ss_mapping(self.permissions)
        # if ss_mapping is None it means there are no sources in it.
        # if it is not None we proceed to run flowdroid
        if ss_mapping is not None:
            # write source and sink mappings to file
            with self.output().open('w') as data_file:
                json.dump(ss_mapping, data_file, indent=2)
                # data_file.write('\n'.join(ss_mapping))
                # else:
                # if there are no automatically granted permission or there are no
                # source mapping found, we write skipped tag to output xml
                # if is_app_skipped:
                #     with self.output().open('w') as f:
                #         # write xml with error flag
                #         xml_header = "<?xml version=\"1.0\" ?>"
                #         open_tags = "<DataFlowResults FileFormatVersion=\"100\">"
                #         skip_tag = "<skipped>NO AUTO-GRANTED</skipped>"
                #         closing_tags = "</DataFlowResults>"
                #         xml_output = xml_header + \
                #                      open_tags + skip_tag + closing_tags
                #         f.write(xml_output + "\n")
                #         return


class FlowDroidWrapper(luigi.Task):
    file_name = luigi.Parameter()
    info = luigi.DictParameter(significant=False)
    flow_json_folder = cfg.permission_flowdroid_json_folder
    flow_run_folder = cfg.permission_flowdroid_run_folder

    def __init__(self, *args, **kwargs):
        super(FlowDroidWrapper, self).__init__(*args, **kwargs)
        self.pkg, _, _ = commons().get_apk_data(self.file_name)

    def requires(self):
        return MakeSourcesSinks(file_name=self.file_name, permissions=self.info['auto_granted'])

    def output(self):
        output_file = os.path.join(self.flow_json_folder,
                                   self.pkg,
                                   self.file_name + ".json")
        return ExternalFileTarget(output_file)

    # creates the json application file
    def run(self):
        with self.input().open() as f:
            ss = json.load(f)
        flowdroid_extra_options = '--contentsources' if ss['with_content_res'] else ''
        yield fl.FlowDroidJson(file_name=self.file_name, flowdroid_sourcessinks=ss['ss_mapping'],
                               flowdroid_extra_options=flowdroid_extra_options,
                               flow_json_folder=self.flow_json_folder, flow_run_folder=self.flow_run_folder)


class FlowDroidApp(luigi.Task):
    apks = luigi.TupleParameter(significant=False)
    pkg = luigi.Parameter()

    # requires json of single releases
    def requires(self):
        perm_tasks = PermissionApp(apks=self.apks, pkg=self.pkg)
        # luigi.build([perm_tasks], local_scheduler=False)

        with perm_tasks.output().open() as data_file:
            app = json.load(data_file)
            for ver, info in app.items():
                if 'auto_granted' in info.keys():
                    yield FlowDroidWrapper(file_name=info['file'], info=info)
                    # task.open()

    # output is the json file with aggregated info of the app
    # noinspection PyTypeChecker
    def output(self):
        output_file = os.path.join(cfg.permission_flowdroid_app_folder,
                                   self.pkg,
                                   self.pkg + ".json")
        return ExternalFileTarget(output_file)

    # creates the json application file
    def run(self):
        # create app dictionary
        app = {'pkg': self.pkg, 'apks': []}

        # for each release, add json data to app dict
        for i in self.input():
            with i.open() as data_file:
                app['apks'].append(json.load(data_file))
        # sort apks list according to version code
        app['apks'] = sorted(app['apks'], key=lambda k: int(k['vercode']))
        with self.output().open('w') as f:
            json.dump(app, f, indent=2)


class ApiEvolution(luigi.Task):
    apks = luigi.TupleParameter(significant=False)
    pkg = luigi.Parameter()

    def requires(self):
        api_loc = AndroguardApiLocation(pkg=self.pkg, apks=self.apks)
        permapp = PermissionApp(pkg=self.pkg, apks=self.apks)
        return {'permapp': permapp,
                'ag_api_loc': api_loc}

    # noinspection PyTypeChecker
    def output(self):
        output_file = os.path.join(cfg.permission_api_evolution_folder,
                                   self.pkg,
                                   self.pkg + ".json")
        return ExternalFileTarget(output_file)

    # returns a list containing in which new locations the api is used
    @staticmethod
    def new_api_locs(last_ver_api, api, locs):
        # if the api was not there in the last version, return all locs
        if api not in last_ver_api.keys():
            return locs
        # else only return the new locations where api is used
        new_locs = []
        for loc in locs:
            if loc not in last_ver_api[api]:
                new_locs.append(loc)
        return new_locs

    # returns the list of candidate permissions for an API,
    # which is the list of permissions required by the API
    @staticmethod
    def get_candidate_perms(api):
        # if the api is content resolver use the related perms from the
        # category
        if utils.is_cr_api(api):
            candidate_perms = utils.get_perm_from_api_categories(api)
        # else check which permissions in androguard mapping maps the api
        else:
            candidate_perms = []
            for perm in DANGEROUS_PERM_LIST:
                # check if the api requires the permission
                if api in AG_MAPPING[perm]:
                    candidate_perms.append(perm)

        return candidate_perms

    # returns the list of permissions required by the api, only
    # considering permissions that were already required in previous
    # version or automatically granted (the user does not not have to
    # grant them)
    def get_api_evo_perms(self, api, apk_perm, prev_ver_apk_perm):
        required_perms = []

        # parse all candidate permissions and,if they are automatically
        # granted or already requested, add them to the return list
        for perm in self.get_candidate_perms(api):
            # check if the permission is requested
            if ('perms' in apk_perm.keys() and
                    perm in apk_perm['perms']):

                # if the permission is automatically granted, add it to
                # the list with a *
                if ('auto_granted' in apk_perm and
                        perm in apk_perm['auto_granted']):
                    required_perms.append(perm + '*')

                # if the permission was granted in the previous version,
                # add it to the list. We skip all newly granted
                # permissions that are not automatically granted
                elif ('perms' in prev_ver_apk_perm and
                      perm in prev_ver_apk_perm['perms']):
                    required_perms.append(perm)

        return required_perms

    # returns, for each app version, the list of added APIs belonging to
    # permissions that were already requested in previous versions
    def api_evo_analysis(self, app_perm, app_apis):
        app_api_evo = {}

        # get iterator over app with versions sorted numerically.
        # get first element and setup variables
        app_it = iter(sorted(app_apis.items(), key=lambda i: int(i[0])))
        ver, api_dict = next(app_it)
        last_ver_apis = api_dict
        last_ver = ver

        # cycle all APIs in all versions
        for ver, api_dict in app_it:
            for api, locs in api_dict.items():

                # get all new locatios where api is used
                new_locs = self.new_api_locs(last_ver_apis, api, locs)

                # if there are no new uses of the api, continue
                if len(new_locs) == 0:
                    continue

                # check which permissions the api needs
                used_perms = self.get_api_evo_perms(api, app_perm[ver],
                                                    app_perm[last_ver])

                # if there are no permissions granted for the api, continue
                if len(used_perms) == 0:
                    continue

                # add key to dictionary if missing. we only want to keep 
                # versions which have new apis added
                if ver not in app_api_evo:
                    app_api_evo[ver] = {}

                # add the data to the dictionary
                app_api_evo[ver][api] = {}
                app_api_evo[ver][api]['locs'] = new_locs
                app_api_evo[ver][api]['perms'] = used_perms
            #                print ver + ' | ' + api + ' | ' + str(new_locs) + ' | ' + str(used_perms)

            # update last_ver_api and app perm
            last_ver_apis = api_dict
            last_ver = ver

        # return the dictionary
        return app_api_evo

    # returns the list of newly requested permissions in input version
    # skipping the automatically granted ones
    @staticmethod
    def get_added_perms(app_perm, ver, prev_ver):
        added_perms = []

        for perm in app_perm[ver]['perms']:
            # skip auto granted permissions
            if ('auto_granted' in app_perm[ver] and
                    perm in app_perm[ver]['auto_granted']):
                continue

            # if the permission is not in the previous version,
            # add it to the return list
            if ('perms' not in app_perm[prev_ver] or
                    perm not in app_perm[prev_ver]['perms']):
                added_perms.append(perm)

        # return the list of newly added permissions
        return added_perms

    def api_added_with_perm(self, app_perm, app_apis):
        app_api_evo = {}

        # get iterator over app with versions sorted numerically.
        # get first element and setup variables
        app_it = iter(sorted(app_apis.items(), key=lambda i: int(i[0])))
        ver, api_dict = next(app_it)
        last_ver = ver

        # cycle all versions
        for ver, api_dict in app_it:

            # if no permission has been added continue
            # we exclude automatically granted perms from this list
            added_perms = self.get_added_perms(app_perm, ver, last_ver)
            if len(added_perms) == 0:
                last_ver = ver
                continue

            # cycle all the apis and add all the ones belonging to
            # a newly asked permission (not auto granted)
            for api, locs in api_dict.items():

                # empty set of used permissions
                used_perms = set()

                # cycle all candidate permissions and add all newly added
                # to the set
                for perm in self.get_candidate_perms(api):
                    if perm in added_perms:
                        used_perms.add(perm)

                # if the api has at least one required permission newly added
                if len(used_perms) > 0:

                    # add key to dictionary if missing. we only want to keep 
                    # versions which have new apis added
                    if ver not in app_api_evo:
                        app_api_evo[ver] = {}

                    # add api to dict for corresponding version
                    app_api_evo[ver][api] = {'locs': locs,
                                             'perms': list(used_perms)}

            # update last_ver_api and app perm
            last_ver = ver

        # return the dictionary
        return app_api_evo

    def run(self):
        app_api_evo = {'base': {}}

        # load input json
        with self.input()['ag_api_loc'].open() as info_file:
            app_apis = json.load(info_file)
        with self.input()['permapp'].open() as info_file:
            app_perm = json.load(info_file)

        app_api_evo['base'] = self.api_added_with_perm(app_perm, app_apis)
        app_api_evo['evo'] = self.api_evo_analysis(app_perm, app_apis)

        with self.output().open('w') as f:
            json.dump(app_api_evo, f, sort_keys=True)


class OverprivilegedApk(luigi.Task):
    """ for each apk euses androguard to extract the list
    of overprivileged permissions """
    file_name = luigi.Parameter()

    # requires path of one single application
    def __init__(self, *args, **kwargs):
        super(OverprivilegedApk, self).__init__(*args, **kwargs)
        self.pkg, self.vercode, self.date = commons().get_apk_data(self.file_name)

    # requires path of one single application
    def requires(self):
        return ApkFile(file_name=self.file_name)

    # creates the json application file
    def output(self):
        output_file = os.path.join(cfg.permission_overprivileged_apk_folder,
                                   self.pkg,
                                   self.file_name + ".json")
        return ExternalFileTarget(output_file)

    def set_androguard_op_permissions(self, apk):
        # surround with try / catch block: if androguard crashes we will
        # use alternative method and check API to see OP permissions
        try:

            # analyze app with androguad
            a, d, dx = androguard.misc.AnalyzeAPK(self.input().path)
            tmp_perms = a.get_permissions()

            # get all android permissions 
            perms = []
            for p in tmp_perms:
                if (p.startswith('android.permission.') and
                        p != ('android.permission.')):
                    perms.append(p)

            # get dictionary of used permissions and APIs
            ps = dx.get_permissions(perms)
            overprivileged = set()

            # check which permissions are never used in the apk
            for p in perms:
                if p not in ps.keys():
                    perm = p[len('android.permission.'):]
                    if perm in DANGEROUS_PERM_LIST:
                        overprivileged.add(perm)

            # add op permissions list to apk dictionary and sort it
            apk['op_perms'] = []
            for op in overprivileged:
                apk['op_perms'].append(op)
            apk['op_perms'].sort()

        except Exception as e:
            print('exception in getting OP perms with androguard' + str(e))

    # get all apk info and dump them on the json file
    def run(self):
        # creat apk dictionary
        apk = {}

        # get op permission data from androguard
        self.set_androguard_op_permissions(apk)

        # write apk to json file
        with self.output().open('w') as f:
            json.dump(apk, f, sort_keys=True)

        # cleanup file
        self.input().cleanup()


class OverprivilegedApp(luigi.Task):
    logger = logging.getLogger('permissions')
    apks = luigi.ListParameter(significant=False)
    pkg = luigi.Parameter()

    androguard_api_folder = luigi.Parameter()
    mapping_cash = {}
    min_sdk = 9

    def requires(self):
        op_apks = [OverprivilegedApk(file_name=apk) for apk in self.apks]
        api_loc_file = os.path.join(cfg.soot_combined_folder, self.pkg,
                                    self.pkg + '.json')
        permapp = PermissionApp(pkg=self.pkg, apks=self.apks)

        return {'op_apks': op_apks,
                'api_loc': ExternalFile(file_name=api_loc_file),
                'perm_app': permapp
                }

    def output(self):
        output_file = os.path.join(cfg.permission_overprivileged_app_folder,
                                   self.pkg,
                                   self.pkg + '.json')
        return ExternalFileTarget(output_file)

    def get_mapping_path(self, target_sdk):
        dest = os.path.join(self.androguard_api_folder, 'androguard_api' + str(target_sdk) + '.txt')
        if target_sdk < self.min_sdk:
            raise IOError("No androguar mapping found")
        if not os.path.exists(dest):
            self.logger.warning("No androguar mapping found for sdk " + str(target_sdk) + "; trying to use lower sdk")
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
        return set([perm if '.' in perm else 'android.permission.' +
                                             perm for perm in app_perms])

    # sets op permissions by looking at API invocation and androguard mappings
    def set_op_perms(self, perm_apis, app, ver, app_perm):

        target_sdk = int(app[ver].get('targetSdkVersion',
                                      app[ver].get('sdkVersion', 19)))
        target_sdk = max(target_sdk, self.min_sdk)
        # load permission mapping
        mapping = self.get_mapping(target_sdk)

        # remove the additional part in case of ContentResolver apis,
        # which are in form <api>(categories), and keep only until the ">'
        api_set = set([api[:api.index('>') + 1] if api.endswith('}') else api
                       for api in perm_apis[ver].keys()])
        used_perm_apis = api_set & set(mapping.keys())

        used_perms = set(itertools.chain.from_iterable(mapping[api] for
                                                       api in used_perm_apis))

        app_perms = self.normalise_perm(app_perm[ver]['perms'])
        # op_perms = app_perms - used_perm_lib - used_perm_native
        op_perms = app_perms - used_perms

        op_perms_list = [p.replace('android.permission.', '') for p in op_perms]
        app[ver]['op_perms'] = op_perms_list

    def run(self):

        app = {}

        # load permission api
        with self.input()['api_loc'].open() as data_file:
            perm_api_loc = json.load(data_file)

        # load permission app
        with self.input()['perm_app'].open() as info_file:
            app_perm = json.load(info_file)

        # for each apk, add info_apk to app[ver] dictionary
        for i in self.input()['op_apks']:
            with i.open() as op_apk_file:
                apk_op = json.load(op_apk_file)
                version = i.path.split("_")[-2]
                app[version] = apk_op

            if 'op_perms' not in app[version].keys():
                self.set_op_perms(perm_api_loc, app, version, app_perm)

        with self.output().open('w') as f:
            json.dump(app, f, sort_keys=True, indent=2)


class PermissionAnalysis(luigi.WrapperTask):
    r = luigi.Parameter(default="", significant=False)
    pkg = luigi.Parameter(default="", significant=False)
    apks_folder = cfg.apks_folder
    apk_list_file = luigi.Parameter(significant=False)

    def get_apps_from_dir(self):
        apps = defaultdict(set)
        for root, dirs, files in os.walk(self.apks_folder):
            for basename in files:
                if basename.endswith('.apk'):
                    pkg, vercode, date = commons.get_apk_data(basename)
                    apps[pkg].add((pkg, vercode, date))
        return apps

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
        if self.r == 'papp' and self.pkg:
            pkg = self.pkg
            return PermissionApp(pkg=pkg, apks=apps[pkg])
        for pkg, apks in apps.items():
            if self.r == 'papp':
                yield PermissionApp(pkg=pkg, apks=apks)
            if self.r == 'autogranted':
                yield AutoGrantedApi(pkg=pkg, apks=apks)
            if self.r == 'apievo':
                yield ApiEvolution(pkg=pkg, apks=apks)
            if self.r == 'flows':
                yield FlowDroidApp(pkg=pkg, apks=apks)
            if self.r == 'op':
                yield OverprivilegedApp(pkg=pkg, apks=apks)


if __name__ == '__main__':
    # apk_list_file parameter necessary!
    luigi.run(main_task_cls=PermissionAnalysis)
