import fnmatch
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from collections import Counter
from collections import defaultdict

import matplotlib


matplotlib.use('Agg')
import luigi
import numpy
import pandas as pd
import xmltodict
from lxml import etree

sys.path.append("..")
import cfg
import lib_utils
import heatmaps
from targets import ExternalFileTarget, ApkFile, ExternalFile
from commons import commons
from constants import CONTENT_RESOLVER_API_LIST, AG_API_DICT, CONTENT_RESOLVER_CAT
logger = logging.getLogger('luigi-interface')

# python luigi_apktool.py ApkStructureAnalysis --local-scheduler
# autopep8 luigi_apktool.py --in-place

def check_unzip_layout_folder(apk_name, dest_dir):
    dest_layout_dir = os.path.join(dest_dir, 'res', 'layout')
    if os.path.exists(dest_layout_dir):
        return
    apk_base_name = os.path.basename(apk_name)
    extract_dir = tempfile.mkdtemp(apk_base_name)
    zip_ref = zipfile.ZipFile(apk_name, 'r')
    zip_ref.extractall(extract_dir)
    zip_ref.close()
    source_layout_dir = os.path.join(extract_dir, 'res', 'layout')
    if not os.path.exists(source_layout_dir):
        return
    shutil.copytree(source_layout_dir, dest_layout_dir)

class ApktoolRun(luigi.Task):

    file_name = luigi.Parameter()

    def __init__(self, *args, **kwargs):
        super(ApktoolRun, self).__init__(*args, **kwargs)
        self.pkg, self.vercode, self.date = commons().get_apk_data(self.file_name)

    # requires path of one single application
    def requires(self):
        return ApkFile(file_name=self.file_name)

    # creates the json application file
    def output(self):
        output_file = os.path.join(cfg.apktool_run_folder,
                                   self.pkg,
                                   self.pkg + "_" +
                                   self.vercode + "_" +
                                   self.date + ".json")
        return ExternalFileTarget(output_file)

    def run(self):
        buf_size = 65536
        fn_md5 = {}
        
        # get the command line for apktool and run it
        outfolder = os.path.join(os.path.dirname(self.output().path),
                                 self.pkg + "_" +
                                 self.vercode + "_" +
                                 self.date + ".out")
        cmd = "./apktool -f --keep-broken-res --no-debug-info " + "d " + self.input().path + " -o " + outfolder
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

        logger.debug('Running apktool command: ' + cmd)
        output, err = process.communicate()
        output = output.decode('utf-8')
        err = err.decode('utf-8')
        if len(err) > 0:            
            logger.error('Apktool error: <' + err + '>\n' + cmd)
        logger.debug('Apktool out: ' + output)

        if not os.path.isfile(os.path.join(outfolder, "AndroidManifest.xml")):
            return
        check_unzip_layout_folder(self.input().path, outfolder)
        # hash every file in out folder of apktool
        for root, dirs, files in os.walk(outfolder):
            for filename in files:
                md5 = hashlib.md5()
                filepath = os.path.join(root, filename)
                with open(filepath, "rb") as f:
                    while True:
                        data = f.read(buf_size)
                        if not data:
                            break
                        md5.update(data)
                fn_md5[filepath.replace(outfolder + "/", "")] = md5.hexdigest()

        self.input().cleanup()
        with self.output().open('w') as f:
            json.dump(fn_md5, f, sort_keys=True)


class SmaliList(luigi.Task):
    apks = luigi.ListParameter()
    pkg = luigi.Parameter()

    def requires(self):
        return [ApktoolRun(file_name=apk) for apk in self.apks]

    def output(self):
        output_file = os.path.join(cfg.apktool_smalilist_folder,
                                   self.pkg,
                                   self.pkg + ".json")
        return ExternalFileTarget(output_file)

    def contains_smali_files(self, files):
        for f in files:
            if f.endswith(".smali"):
                return True
        return False

    def prefix_already_added(self, pkgname, pkg_set):
        for pkg in pkg_set:
            if pkg in pkgname:
                return True
        return False

    def run(self):
        pkg_smalilist = {}

        for i in self.input():
            smalilist = set()
            vercode = i.path.split("_")[-2]
            smali_folder = os.path.join(i.path.replace(".json", ".out"), "smali")
            if os.path.isdir(smali_folder):
                for root, dirs, files in os.walk(smali_folder, topdown=True):
                    # stop recursion at depth 4
                    depth = root[len(smali_folder):].count(os.path.sep)
                    if depth == 4:
                        dirs[:] = []
                    directory = root[len(smali_folder) + len(os.path.sep):]
                    if self.contains_smali_files(files) and not self.pkg.replace(".",
                                                                                 os.path.sep) in directory and not self.prefix_already_added(
                        directory, smalilist):
                        smalilist.add(directory)
                pkg_smalilist[vercode] = list(smalilist)

        self.input().cleanup()
        
        with self.output().open('w') as f:
            json.dump(pkg_smalilist, f, sort_keys=True)


class APIDiff(luigi.Task):
    pkg = luigi.Parameter()
    apks = luigi.ListParameter()

    def requires(self):
        return ExtractApi(pkg=self.pkg, apks=self.apks)

    def output(self):
        output_file = os.path.join(cfg.apktool_api_diff_folder,
                                   self.pkg,
                                   self.pkg + ".json")
        return ExternalFileTarget(output_file)

    def run(self):
        api_delta = {}
        with self.input().open("r") as f:
            versions = json.load(f)
            versions_it = iter(sorted(versions.items(), key=lambda i: int(i[0])))
            old_api = next(versions_it)[1]
            for vercode, apis in versions_it:
                new_api = apis
                native_delta = self.compare_api(old_api['native'], new_api['native'])
                lib_delta = self.compare_api(old_api['lib'], new_api['lib'])
                old_api = new_api
                api_delta[vercode] = {'native': native_delta, 'lib': lib_delta}

        with self.output().open('w') as f:
            json.dump(api_delta, f, sort_keys=True)

    def compare_api(self, old_api, new_api):
        deleted_items = set(old_api.keys()) - set(new_api.keys())
        new_items = set(new_api.keys()) - set(old_api.keys())
        updated_items = set(old_api.keys()) & set(new_api.keys())
        changed_items = {}
        for item in updated_items:
            delta = new_api[item] - old_api[item]
            changed_items[item] = delta
        return {'deleted': {el: 1 for el in deleted_items}, 'added': {el: 1 for el in new_items},
                'changed': changed_items, "old_apis": len(old_api)}


class ExtractPermissionApi(luigi.Task):
    pkg = luigi.Parameter()
    apks = luigi.ListParameter()
    perm_mapping = luigi.Parameter()

    def requires(self):
        return ExtractApi(pkg=self.pkg, apks=self.apks)

    def output(self):
        output_file = os.path.join(cfg.apktool_permission_api_folder,
                                   self.pkg,
                                   self.pkg + ".json")
        return ExternalFileTarget(output_file)

    def run(self):
        # laod apis from previous luigi task
        with open(self.input().path) as data_file:
            apis = json.load(data_file)

        # load permission mappings
        with open(self.perm_mapping) as data_file:
            mapping = [x.split(';')[0].strip() for x in data_file.readlines()]

        perm_apis = {}

        # filter only APIs present in permission mappings
        for ver, data in apis.items():
            lib = {}
            for api, count in data['lib'].items():
                if api in mapping:
                    lib[api] = count

            native = {}
            for api, count in data['native'].items():
                if api in mapping:
                    native[api] = count

            perm_apis[ver] = {}
            perm_apis[ver]['lib'] = lib
            perm_apis[ver]['native'] = native

        self.input().cleanup()

        with self.output().open('w') as f:
            json.dump(perm_apis, f, sort_keys=True)


class ExtractApi(luigi.Task):
    apks = luigi.ListParameter()
    pkg = luigi.Parameter()
    android_api_list_file = luigi.Parameter()

    types = {'V': "void", 'Z': "boolean", 'I': "int", 'F': "float", 'J': "long", 'D': "double", 'B': "byte",
             'C': "char", 'S': "short"}
    param_regex = re.compile('(?P<obj>\[*L[^;]+?;)|(?P<prim>\[*[ZIFJBDCS])')

    def split_param(self, arg):
        arg = arg.replace("/", ".")
        matches = re.findall(self.param_regex, arg)
        return [self.convert_type(x or y) for x, y in matches]

    def convert_type(self, arg):
        array_count = arg.count('[')
        arg = arg.strip('[')
        if arg in self.types.keys():
            res = self.types[arg]
        else:
            res = arg.strip("L;").replace("/", ".")
        return res + '[]' * array_count

    def is_android_class(self, class_name):
        # signature in self.android_api_list
        if class_name.startswith("android") or \
           class_name.startswith("com.android") or \
           class_name.startswith("com.google.android") or \
           class_name.startswith("dalvik") or \
           class_name.startswith("java.io") or \
           class_name.startswith("java.nio") or \
           class_name.startswith("java.net") or \
           class_name.startswith("org.apache.http"):  # TODO replace java classes with the list of signatures
            return True
        return False

    def extract_API_calls(self, currentDir):
        apis = {}
        pkg_prefix = lib_utils.LibProvider.get_reduced_pkg(self.pkg)
        countAPI = defaultdict(int)
        countAPI_lib = defaultdict(int)
        for dirpath, dirnames, filenames in os.walk(currentDir):
            for filename in fnmatch.filter(filenames, "*.smali"):
                path_smali_file = os.path.join(dirpath, filename)
                file_loc = path_smali_file.replace(currentDir, "").strip("/")
                f = open(path_smali_file)
                text = f.read()
                f.close()
                API_call = re.findall('invoke(.*)', text)
                for api in API_call:
                    class_api = re.search('}, (.*);->', api)
                    if class_api:
                        class_api = class_api.group().replace("}, ", "")
                        class_api = class_api.replace(";->", "")
                        class_api = class_api.replace("/", ".")
                        class_api = class_api.strip("L;")
                    # filter obfuscated class
                    if class_api and len(class_api) > 2:
                        # get method and return value
                        method_call = re.search('->(.*)', api)
                        if method_call:
                            method_call = method_call.group().replace("->", "")
                            parameters_line = re.findall('\(.*\)', method_call)
                            method_values = re.split('\(.*\)', method_call)
                            ret_type = self.convert_type(method_values[1])
                            m_name = method_values[0]
                            parameters = self.split_param(parameters_line[0])
                            # filter obfuscated calls
                            if len(method_values[0]) > 1:
                                signature = "<" + class_api + ": " + ret_type + " " + m_name + "(" + ",".join(
                                    parameters) + ")>"
                                # listAPIs.append(signature)
                                # APIkey = (classAPI, ret_type, m_name, ",".join(parameters))
                                if self.is_android_class(class_api):
                                    if file_loc.startswith(pkg_prefix):
                                        countAPI[signature] += 1
                                    else:
                                        countAPI_lib[signature] += 1
        apis['native'] = countAPI
        apis['lib'] = countAPI_lib
        return apis

    def load_api_list(self):
        with open(self.android_api_list_file, 'r') as f:
            self.android_api_list = {x.strip() for x in f.readlines()}

    def requires(self):
        return [ApktoolRun(file_name=apk) for apk in self.apks]

    def output(self):
        output_file = os.path.join(cfg.apktool_api_folder,
                                   self.pkg,
                                   self.pkg + ".json")
        return ExternalFileTarget(output_file)

    def contains_smali_files(self, files):
        for f in files:
            if f.endswith(".smali"):
                return True
        return False

    def prefix_already_added(self, pkgname, pkg_set):
        for pkg in pkg_set:
            if pkg in pkgname:
                return True
        return False

    def run(self):
        pkg_apis = {}
        self.load_api_list()
        for i in self.input():
            vercode = i.path.split("_")[-2]
            smali_folder = os.path.join(i.path.replace(".json", ".out"), "smali")
            apis = self.extract_API_calls(smali_folder)
            pkg_apis[vercode] = apis

        self.input().cleanup()

        with self.output().open('w') as f:
            json.dump(pkg_apis, f, sort_keys=True)

class ExtractApiLocation(luigi.Task):
    apks = luigi.ListParameter()
    pkg = luigi.Parameter()

    types = {'V': "void", 'Z': "boolean", 'I': "int", 'F': "float",'J': "long",
             'D': "double", 'B': "byte",'C': "char", 'S': "short"}
    param_regex = re.compile('(?P<obj>\[*L[^;]+?;)|(?P<prim>\[*[ZIFJBDCS])')

    def split_param(self, arg):
        arg = arg.replace("/", ".")
        matches = re.findall(self.param_regex, arg)
        return [self.convert_type(x or y) for x, y in matches]

    def convert_type(self, arg):
        array_count = arg.count('[')
        arg = arg.strip('[')
        if arg in self.types.keys():
            res = self.types[arg]
        else:
            res = arg.strip("L;").replace("/", ".")
        return res + '[]' * array_count

    def extract_API_calls_location(self, currentDir):
        apis = {}
        uri_categories = set()

        pkg_prefix = lib_utils.LibProvider.get_reduced_pkg(self.pkg)
        for dirpath, dirnames, filenames in os.walk(currentDir):
            for filename in fnmatch.filter(filenames, "*.smali"):
                path_smali_file = os.path.join(dirpath, filename)
                file_loc = path_smali_file.replace(currentDir, "").strip("/")
                f = open(path_smali_file)
                text = f.read()
                f.close()

                # look for possible content_uri strings, if any is found add them
                # to uri_categories
                found_uris = re.findall('|'.join(CONTENT_RESOLVER_CAT.keys()), text)
                # found_uris = re.findall('(' + '|'.join(CONTENT_RESOLVER_CAT.keys())+ '.*)', text)
                found_cats = set([CONTENT_RESOLVER_CAT[uri] for uri in found_uris])
                uri_categories.update(found_cats)

                API_call = re.findall('invoke(.*)', text)
                for api in API_call:
                    class_api = re.search('}, (.*);->', api)
                    if class_api:
                        class_api = class_api.group().replace("}, ", "")
                        class_api = class_api.replace(";->", "")
                        class_api = class_api.replace("/", ".")
                        class_api = class_api.strip("L;")
                    # filter obfuscated class
                    if class_api and len(class_api) > 2:
                        # get method and return value
                        method_call = re.search('->(.*)', api)
                        # TODO: try to extract actual parameter values
                        if method_call:
                            method_call = method_call.group().replace("->", "")
                            parameters_line = re.findall('\(.*\)', method_call)
                            method_values = re.split('\(.*\)', method_call)
                            ret_type = self.convert_type(method_values[1])
                            m_name = method_values[0]
                            parameters = self.split_param(parameters_line[0])
                            # filter obfuscated calls
                            if len(method_values[0]) > 1:
                                signature = "<" + class_api + ": " + ret_type + " " + m_name
                                signature += "(" + ",".join(parameters) + ")>"

                                # skipping apis not in Androguard API DICT
                                if signature in AG_API_DICT:

                                    # if the signature is a Content Resolver signature and we
                                    # have found uri in this file, we add those URI as possible
                                    # content resolver categories. otherwise we add ()
                                    # to the signature and will later fill it with URI
                                    if signature in CONTENT_RESOLVER_API_LIST:
                                        if len(found_uris) > 0:
                                            signature += '{' + ','.join(found_cats) + '}'
                                        else:
                                            signature += '{}'

                                    # get the api location
                                    if file_loc.startswith(pkg_prefix):
                                        loc = 'appcode'
                                    else:
                                        loc = dirpath.replace(currentDir, "").strip("/")

                                    # add the signature location to the api dictionary
                                    if signature not in apis.keys():
                                        apis[signature] = []
                                    if loc not in apis[signature]:
                                        apis[signature].append(loc)

        # TODO after parsing all smali files, add all cat in uri_categories
        # to all content resolver apis that still have none
        for api in apis.keys():
            if api.endswith('{}'):
                new_api = api[:-1] + ','.join(uri_categories) + '}'
                apis[new_api] = apis.pop(api)


        return apis

    def requires(self):
        return [ApktoolRun(file_name=apk) for apk in self.apks]

    def output(self):
        output_file = os.path.join(cfg.apktool_api_location_folder,
                                   self.pkg,
                                   self.pkg + ".json")
        return ExternalFileTarget(output_file)

    def contains_smali_files(self, files):
        for f in files:
            if f.endswith(".smali"):
                return True
        return False

    def prefix_already_added(self, pkgname, pkg_set):
        for pkg in pkg_set:
            if pkg in pkgname:
                return True
        return False

    def run(self):
        pkg_apis = {}
        for i in self.input():
            vercode = i.path.split("_")[-2]
            smali_folder = os.path.join(i.path.replace(".json", ".out"), "smali")
            apis = self.extract_API_calls_location(smali_folder)
            pkg_apis[vercode] = apis

        self.input().cleanup()
        
        with self.output().open('w') as f:
            json.dump(pkg_apis, f, sort_keys=True)


class OutFileDiff(luigi.Task):
    apks = luigi.ListParameter()
    pkg = luigi.Parameter()

    # requires json of single releases
    def requires(self):
        return [ApktoolRun(file_name=apk) for apk in self.apks]

    # output is the json file with aggregated info of the app
    def output(self):
        output_file = os.path.join(cfg.apktool_file_diff_folder,
                                   self.pkg,
                                   self.pkg + ".json")
        return ExternalFileTarget(output_file)

    # get detailed information about differences between two releases
    def do_detailedcomparison(self, apps, i):
        out_diff = {}

        jsonfile_old = apps[i]
        jsonfile_new = apps[i + 1]

        outfolder_old = apps[i][:apps[i].rindex(".")] + ".out"
        outfolder_new = apps[i + 1][:apps[i + 1].rindex(".")] + ".out"

        xmlfile_old = os.path.join(outfolder_old, "AndroidManifest.xml")
        xmlfile_new = os.path.join(outfolder_new, "AndroidManifest.xml")
        manifest_diff = self.get_manifest_diff(xmlfile_old, xmlfile_new)
        smali_diff = self.get_changedfile_number(jsonfile_old, jsonfile_new, "smali")
        smali_diff["old_files_counts"] = self.get_file_number(
            os.path.join(outfolder_old, "smali"))

        resfolder_old = os.path.join(outfolder_old, "res")
        resfolder_new = os.path.join(outfolder_new, "res")
        res_diff = self.get_res_diff(
            resfolder_old, resfolder_new, jsonfile_old, jsonfile_new)
        res_diff["old_files_counts"] = self.get_file_number(
            os.path.join(outfolder_old, "res"))

        out_diff["manifest"] = manifest_diff
        out_diff["smali"] = smali_diff
        out_diff["res"] = res_diff

        return out_diff

    # function for getting number of files in a certain folder.
    def get_file_number(self, folderpath):
        file_number = 0
        for root, dirs, files in os.walk(folderpath):
            if files != []:
                file_number = file_number + len(files)
        return file_number

    def get_manifest_diff(self, xmlfile_old, xmlfile_new):
        manifest_diff = {}
        with open(xmlfile_old, "rb") as fd1, open(xmlfile_new, "rb") as fd2:
            doc1 = xmltodict.parse(fd1.read(),
                                   force_list={"activity", "uses-permission", "service", "provider", "receiver"})
            doc2 = xmltodict.parse(fd2.read(),
                                   force_list={"activity", "uses-permission", "service", "provider", "receiver"})
            app1 = doc1["manifest"]["application"]
            app2 = doc2["manifest"]["application"]

            manifest_diff["permission"] = self.get_dictlist_diff(
                doc1["manifest"], doc2["manifest"], "uses-permission")

            manifest_diff["activity"] = self.get_dictlist_diff(app1, app2, "activity")
            manifest_diff["service"] = self.get_dictlist_diff(app1, app2, "service")
            manifest_diff["provider"] = self.get_dictlist_diff(app1, app2, "provider")
            manifest_diff["receiver"] = self.get_dictlist_diff(
                app1, app2, "receiver")
        return manifest_diff

    def get_smali_diff(self, resfolder_old, resfolder_new, jsonfile_old, jsonfile_new):
        pass

    def get_res_diff(self, resfolder_old, resfolder_new, jsonfile_old, jsonfile_new):
        drawablefolders1 = []
        layoutfolders_old = set()
        valuesfolders1 = []
        drawablefolders2 = []
        layoutfolders_new = set()
        valuesfolders2 = []
        res_diff = {}
        drawable_file_number = 0
        layout_file_number = 0
        values_file_number = 0

        # get all the folders whose names start with "drawable", "layout", "values" separately
        # count number of files inside those folders.
        # the previous release.
        for root, dirs, files in os.walk(resfolder_old):
            if dirs != []:
                for dir1 in dirs:
                    if dir1.startswith("drawable"):
                        drawablefolders1.append(dir1)
                        drawable_file_number = drawable_file_number + \
                                               self.get_file_number(os.path.join(root, dir1))
                    if dir1.startswith("layout"):
                        layoutfolders_old.add(dir1)
                        layout_file_number = layout_file_number + \
                                             self.get_file_number(os.path.join(root, dir1))
                    if dir1.startswith("values"):
                        valuesfolders1.append(dir1)
                        values_file_number = values_file_number + \
                                             self.get_file_number(os.path.join(root, dir1))

        for root, dirs, files in os.walk(resfolder_new):
            if dirs != []:
                for dir2 in dirs:
                    if dir2.startswith("drawable"):
                        drawablefolders2.append(dir2)
                    if dir2.startswith("layout"):
                        layoutfolders_new.add(dir2)
                    if dir2.startswith("values"):
                        valuesfolders2.append(dir2)

        res_drawable_diff = self.get_changedfile_number(
            jsonfile_old, jsonfile_new, os.path.join("res", "drawable"))
        res_drawable_diff["diff"] = self.get_list_diff(
            drawablefolders1, drawablefolders2)
        res_drawable_diff["old_files_counts"] = drawable_file_number

        res_layout_diff = {}

        res_layout_diff["old_files_counts"] = layout_file_number
        changed, added, removed, modification, insertion, deletion = self.get_folders_diff(resfolder_old, resfolder_new,
                                                                                           layoutfolders_old,
                                                                                           layoutfolders_new)
        res_layout_diff["changed"] = changed
        res_layout_diff["added"] = added
        res_layout_diff["removed"] = removed
        res_layout_diff["modification"] = modification
        res_layout_diff["insertion"] = insertion
        res_layout_diff["deletion"] = deletion
        res_values_diff = self.get_changedfile_number(
            jsonfile_old, jsonfile_new, os.path.join("res", "values"))
        res_values_diff["diff"] = self.get_list_diff(
            valuesfolders1, valuesfolders2)
        res_values_diff["old_files_counts"] = values_file_number

        res_diff["drawable"] = res_drawable_diff
        res_diff["layout"] = res_layout_diff
        res_diff["values"] = res_values_diff
        return res_diff

    def get_folders_diff(self, old_folder_path, new_folder_path, old_folder_set, new_folder_set):
        total_changed = 0
        total_added = 0
        total_removed = 0
        total_modification = 0
        total_insertion = 0
        total_deletion = 0
        total_m_lines = 0
        total_i_lines = 0
        total_d_lines = 0
        for folder in old_folder_set & new_folder_set:
            old_full_path = os.path.join(old_folder_path, folder)
            new_full_path = os.path.join(new_folder_path, folder)
            # changed, added, removed, modification, insertion, deletion = self.get_folder_diff(old_full_path, new_full_path)
            changed, added, removed, modification, insertion, deletion, m_lines, i_lines, d_lines = self.get_table_folder_diff(
                old_full_path, new_full_path)
            total_changed += changed
            total_added += added
            total_removed += removed
            total_modification += modification
            total_insertion += insertion
            total_deletion += deletion
            total_m_lines += m_lines
            total_i_lines += i_lines
            total_d_lines += d_lines

        total_removed += len(old_folder_set - new_folder_set)
        total_added += len(new_folder_set - old_folder_set)
        m_ratio = total_modification / float(total_m_lines) if total_modification > 0 else 0
        i_ratio = total_insertion / float(total_i_lines) if total_insertion > 0 else 0
        d_ratio = total_deletion / float(total_d_lines) if total_deletion > 0 else 0
        return total_changed, total_added, total_removed, m_ratio, i_ratio, d_ratio

    def get_file_len(self, fname):
        p = subprocess.Popen(['wc', '-l', fname], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result, err = p.communicate()
        if p.returncode != 0:
            raise IOError(err)
        return int(result.strip().split()[0])

    def get_table_folder_diff(self, old_folder_path, new_folder_path):
        changed = 0
        added = 0
        removed = 0
        modification = 0
        insertion = 0
        deletion = 0
        m_lines = 0
        i_lines = 0
        d_lines = 0
        cmd = "diff -i -E -w -B " + old_folder_path + " " + new_folder_path + " | diffstat -b -K -m -t "
        # " -S " + old_folder_path + " -D " + new_folder_path
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output, err = process.communicate()
        output = output.decode('UTF-8').split('\n')
        # INSERTED,DELETED,MODIFIED,FILE-ADDED,FILE-DELETED,FILE-BINARY,FILENAME
        # deprecated INSERTED,DELETED,MODIFIED,UNCHANGED,FILE-ADDED,FILE-DELETED,FILE-BINARY,FILENAME used with -S -D
        pp = re.compile("^(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(.+)$")
        for line in output:
            if pp.match(line):
                r = pp.search(line)
                insertion = int(r.group(1))
                deletion = int(r.group(2))
                modification = int(r.group(3))
                changed += 1  # file changed
                added += int(r.group(4))
                removed += int(r.group(5))
                fname = r.group(7)
                base_fname = os.path.basename(fname)
                if insertion + deletion + modification > 0:
                    f_len = self.get_file_len(os.path.join(old_folder_path, base_fname))
                if modification > 0:
                    m_lines += f_len
                if insertion > 0:
                    i_lines += f_len
                if deletion > 0:
                    d_lines += f_len
        return changed, added, removed, modification, insertion, deletion, m_lines, i_lines, d_lines

    def get_folder_diff(self, old_folder_path, new_folder_path):
        changed = 0
        added = 0
        removed = 0
        modification = 0
        insertion = 0
        deletion = 0
        cmd = "diff -i -E -w -B -r " + old_folder_path + " " + new_folder_path + " | diffstat -b -K -m -s " + \
              " -S " + old_folder_path + " -D " + new_folder_path
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output, err = process.communicate()
        output = output.decode('UTF-8')
        # this is highly dependent on the OS !
        # 5 files changed, 2 insertions(+), 2 deletions(-), 6 modifications(!), 75 unchanged lines(=), 1 file added, 31 files removed
        if "files changed" in output:
            changed = int(re.search("(\d+) file[s]? changed", output).group(1))
        if "insertion" in output:
            insertion = int(re.search("(\d+) insertion", output).group(1))
        if "deletion" in output:
            deletion = int(re.search("(\d+) deletion", output).group(1))
        if "modification" in output:
            modification = int(re.search("(\d+) modification", output).group(1))
        if "added" in output:
            added = int(re.search("(\d+) file[s]? added", output).group(1))
        if "removed" in output:
            removed = int(re.search("(\d+) file[s]? removed", output).group(1))
        return changed, added, removed, modification, insertion, deletion

    def get_changedfile_number(self, jsonfile_old, jsonfile_new, folder):
        changedfile_number = {}
        with open(jsonfile_old) as data_file_old, open(jsonfile_new) as data_file_new:
            json_old = json.load(data_file_old)
            json_new = json.load(data_file_new)

            filtred_keys_old = set(filter(lambda filename: filename.startswith(folder), json_old.keys()))
            filtred_keys_new = set(filter(lambda filename: filename.startswith(folder), json_new.keys()))

            remove = len(filtred_keys_old - filtred_keys_new)
            add = len(filtred_keys_new - filtred_keys_old)
            change = 0
            for filename in (filtred_keys_old & filtred_keys_new):
                if json_old[filename] != json_new[filename]:
                    change += 1
        changedfile_number["add"] = add
        changedfile_number["remove"] = remove
        changedfile_number["change"] = change
        return changedfile_number

    def get_objects_dict(self, source):
        res = {}
        for item in source:
            # android:name for the activity must be always specified according to the documentation
            # 'default' should be never set here
            # duplicates, assume only in permissions
            name = item.get("@android:name", "default")
            if (name in res.keys()):
                item['counter'] = item.get('counter', '1')
            res[name] = item
        return (res)

    '''inefficient but works with nested dicts'''

    def deep_dict_equals(self, dict_old, dict_new):
        hash_old = hash(json.dumps(dict_old, sort_keys=True))
        hash_new = hash(json.dumps(dict_new, sort_keys=True))
        return (hash_old == hash_new)

    def get_dictlist_diff(self, source_old, source_new, key):
        list_old = source_old.get(key, [])
        list_new = source_new.get(key, [])
        dict_old = self.get_objects_dict(list_old)
        dict_new = self.get_objects_dict(list_new)
        names_old = set(dict_old.keys())
        names_new = set(dict_new.keys())
        list_diff = {}
        add_items = len(names_new - names_old)
        remove_items = len(names_old - names_new)
        changed_items = 0
        for item in (names_old & names_new):
            if not self.deep_dict_equals(dict_old.get(item), dict_new.get(item)):
                changed_items += 1
        list_diff["add"] = add_items
        list_diff["remove"] = remove_items
        list_diff["changed"] = changed_items
        return list_diff

    def get_list_diff(self, list_old, list_new):
        list_diff = {}
        set_old = set(list_old)
        set_new = set(list_new)
        list_diff["add"] = list(set_new - set_old)
        list_diff["remove"] = list(set_old - set_new)
        return list_diff

    def atoi(self, text):
        return int(text) if text.isdigit() else text

    def natural_keys(self, text):
        return [self.atoi(c) for c in re.split('(\d+)', text)]

    # creates the json application file
    def run(self):
        out_json = []
        pkg_diff = {}
        for i in self.input():
            out_json.append(i.path)
        out_json.sort(key=self.natural_keys)

        for i in range(len(out_json) - 1):
            pkg_diff[out_json[i + 1].split("_")[-2]] = self.do_detailedcomparison(out_json, i)

        for i in self.input():
            i.cleanup()

        with self.output().open('w') as f:
            json.dump(pkg_diff, f, sort_keys=True)


# task to create the heatmap matrix
class ManifestMatrix(luigi.Task):
    apks = luigi.ListParameter()
    pkg = luigi.Parameter()

    # requires application json
    def requires(self):
        return {'json': OutFileDiff(pkg=self.pkg, apks=self.apks)}

    # output is the heatmap
    def output(self):
        output_file = os.path.join(cfg.apktool_manifest_matrix_folder,
                                   self.pkg,
                                   self.pkg + ".json")
        return ExternalFileTarget(output_file)

    # creates the matrix
    def get_matrix(self, app):
        # get all source-sink combinations as y-labels
        ylabels = []
        for apk in app['apks']:
            for data in apk['data'].keys():
                if data not in ylabels:
                    ylabels.append(data)
        ylabels.sort()

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

    def run(self):
        # create app dictionary

        app = {'pkg': self.pkg, 'apks': []}
        with open(self.input()['json'].path) as data_file:
            pkg_diff = json.load(data_file)

            for apkversion, data in pkg_diff.items():
                apk = {}
                apk['vercode'] = apkversion
                apk_data = {}

                apk_data['activity_add'] = data[
                    'manifest']['activity']['add']
                apk_data['activity_remove'] = data[
                    'manifest']['activity']['remove']
                apk_data['activity_changed'] = data[
                    'manifest']['activity']['changed']
                apk_data['permission_add'] = data[
                    'manifest']['permission']['add']
                apk_data['permission_remove'] = data[
                    'manifest']['permission']['remove']
                apk_data['permission_changed'] = data[
                    'manifest']['permission']['changed']
                apk_data['provider_add'] = data[
                    'manifest']['provider']['add']
                apk_data['provider_remove'] = data[
                    'manifest']['provider']['remove']
                apk_data['provider_changed'] = data[
                    'manifest']['provider']['changed']
                apk_data['receiver_add'] = data[
                    'manifest']['receiver']['add']
                apk_data['receiver_remove'] = data[
                    'manifest']['receiver']['remove']
                apk_data['receiver_changed'] = data[
                    'manifest']['receiver']['changed']
                apk_data['service_add'] = data[
                    'manifest']['service']['add']
                apk_data['service_remove'] = data[
                    'manifest']['service']['remove']
                apk_data['service_changed'] = data[
                    'manifest']['service']['changed']
                apk['data'] = apk_data
                app['apks'].append(apk)
        app['apks'] = sorted(app['apks'], key=lambda k: int(k['vercode']))

        matrix, ylabels, xlabels = self.get_matrix(app)
        data = {'m': matrix.tolist(),
                'yl': ylabels,
                'xl': xlabels}

        # write matrix to json file
        with self.output().open('w') as data_file:
            json.dump(data, data_file)


class ManifestHeatmap(luigi.Task):
    apks = luigi.ListParameter()
    pkg = luigi.Parameter()
    app_info_folder = cfg.info_app_folder

    # requires application json
    def requires(self):
        appinfo_file = os.path.join(self.app_info_folder,
                                    self.pkg,
                                    self.pkg + '.json')
        return {'matrix': ManifestMatrix(pkg=self.pkg, apks=self.apks),
                'app_info': ExternalFile(file_name=appinfo_file)}

    # output is the heatmap
    def output(self):
        output_file = os.path.join(cfg.apktool_manifest_heatmap_folder,
                                   self.pkg + "_Manifest.pdf")
        return ExternalFileTarget(output_file)

    def get_app_info(self):
        with self.input()['app_info'].open() as data_file:
            return json.load(data_file)

    def create_heatmap(self, data, row_labels, col_labels):
        sorted_labels = ['activity_add', 'activity_remove',
                         'activity_changed', 'permission_add ', 'permission_remove',
                         'permission_change', 'provider_add', 'provider_remove',
                         'provider_changed', 'receiver_add', 'receiver_remove',
                         'receiver_changed', 'service_add', 'service_remove',
                         'service_changed']
        pdata = pd.DataFrame(data, index=row_labels, columns=col_labels)
        pdata.index.name = "Manifest"
        pdata.columns.name = "Versions"
        app_info = self.get_app_info()
        col_colors = heatmaps.get_col_colors(col_labels, app_info)
        vmax = pdata.values.max()
        splot = heatmaps.plot_heatmap(pdata, vmax=vmax, sorted_labels=sorted_labels, col_colors=col_colors)

        # create output folder if it does not exist
        if not os.path.exists(os.path.dirname(self.output().path)):
            os.makedirs(os.path.dirname(self.output().path))
        splot.savefig(os.path.abspath(self.output().path), format='pdf')

    def run(self):
        # read app matrix from json
        with open(self.input()['matrix'].path) as data_file:
            data = json.load(data_file)

        # get matrix and create the heatmap
        matrix = numpy.array(data['m'])
        self.create_heatmap(matrix, data['yl'], data['xl'])


class ApktoolMatrix(luigi.Task):
    apks = luigi.ListParameter()
    pkg = luigi.Parameter()

    # requires application json
    def requires(self):
        return {'json': OutFileDiff(pkg=self.pkg, apks=self.apks)}

    # output is the heatmap
    def output(self):
        output_file = os.path.join(cfg.apktool_layout_matrix_folder,
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
        # ylabels.sort()
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

    def get_percentage(self, dictionary):
        changed = dictionary['add'] + dictionary['remove'] + dictionary['change']
        # to prevent div by zero for empty folders
        pct = float(changed) / max(1, changed, dictionary['old_files_counts'])
        return pct

    # creates the matrix
    def run(self):
        # create app dictionary
        app = {'pkg': self.pkg, 'apks': []}

        with open(self.input()['json'].path) as data_file:
            pkg_diff = json.load(data_file)
            for apkversion, data in pkg_diff.items():
                apk = {}
                apk['vercode'] = apkversion
                apk_data = {}

                apk_data['smali'] = self.get_percentage(data['smali'])
                apk_data['values'] = self.get_percentage(data['res']['values'])
                apk_data['drawable'] = self.get_percentage(data['res']['drawable'])
                # apk_data['layout'] = self.get_percentage(data['res']['layout'])
                apk_data["changed"] = data['res']["layout"]["changed"] * 1.0 / data['res']["layout"][
                    "old_files_counts"] if data['res']["layout"]["old_files_counts"] > 0 else -1
                apk_data["added"] = data['res']["layout"]["added"] * 1.0 / data['res']["layout"]["old_files_counts"] if \
                    data['res']["layout"]["old_files_counts"] > 0 else -1
                apk_data["removed"] = data['res']["layout"]["removed"] * 1.0 / data['res']["layout"][
                    "old_files_counts"] if data['res']["layout"]["old_files_counts"] > 0 else -1

                apk_data["modification"] = data['res']["layout"]["modification"]
                apk_data["insertion"] = data['res']["layout"]["insertion"]
                apk_data["deletion"] = data['res']["layout"]["deletion"]
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


class ApktoolHeatmap(luigi.Task):
    apks = luigi.ListParameter()
    pkg = luigi.Parameter()
    app_info_folder = cfg.info_app_folder

    # requires application json
    def requires(self):
        appinfo_file = os.path.join(self.app_info_folder,
                                    self.pkg,
                                    self.pkg + '.json')

        return {'matrix': ApktoolMatrix(pkg=self.pkg, apks=self.apks),
                'app_info': ExternalFile(file_name=appinfo_file)}

    # output is the heatmap
    def output(self):
        output_file = os.path.join(cfg.apktool_layout_heatmap_folder,
                                   self.pkg + ".pdf")
        return ExternalFileTarget(output_file)

    def get_app_info(self):
        with self.input()['app_info'].open() as data_file:
            return json.load(data_file)

    # creates the heatmap of permission use and saves it to a file
    def create_heatmap(self, data, row_labels, col_labels):
        sorted_labels = ['changed', 'added', 'removed', 'modification', 'insertion', 'deletion', 'drawable', 'values',
                         'smali']
        pdata = pd.DataFrame(data, index=row_labels, columns=col_labels)
        pdata.index.name = "Manifest"
        pdata.columns.name = "Versions"
        app_info = self.get_app_info()
        col_colors = heatmaps.get_col_colors(col_labels, app_info)
        vmax = pdata.values.max()
        splot = heatmaps.plot_heatmap(pdata, vmax=vmax, sorted_labels=sorted_labels, col_colors=col_colors)
        splot.ax_heatmap.hlines([3, 6, 8], *splot.ax_heatmap.get_xlim(), linewidth=0.5, linestyle='dotted')

        # create output folder if it does not exist
        if not os.path.exists(os.path.dirname(self.output().path)):
            os.makedirs(os.path.dirname(self.output().path))
        splot.savefig(os.path.abspath(self.output().path), format='pdf')

    # creates the heatmap
    def run(self):
        # create output directory if missing
        if not os.path.isdir(os.path.dirname(self.output().path)):
            os.makedirs(os.path.dirname(self.output().path))

        # read app matrix from json
        with open(self.input()['matrix'].path) as data_file:
            data = json.load(data_file)

        # get matrix and create the heatmap
        matrix = numpy.array(data['m'])
        self.create_heatmap(matrix, data['yl'], data['xl'])


class Layouts:
    blacklist = ["Layout", "ScrollView", "fragment", "Fragment", "include", "merge", "AdapterView",
                 "FragmentBreadCrumbs", "LayoutCompat", "PagerTitleStrip", "RecyclerView", "Drawer", "Toolbar",
                 "TvView", "ViewPager", "CardView", "GridView"]

    def get_attr(self, node, attr_name):
        return node.attrib.get('{' + self.ns + '}' + attr_name, "")

    def filter_element(self, el):
        for item in self.blacklist:
            if el.endswith(item):
                return True
        return False

    def get_layouts(self, file_name):
        tree = etree.parse(file_name, parser=etree.XMLParser(remove_comments=True, recover=True))
        root = tree.getroot()
        node_list = []
        self.ns = list(root.nsmap.values())[0] if root.nsmap is not None and len(root.nsmap) != 0 else ""
        for node in root.iter():
            tag = node.tag
            if self.filter_element(tag):
                continue
            id_tag = self.get_attr(node, 'id')
            text = self.get_attr(node, 'text')
            icon = self.get_attr(node, 'src')
            node_value = [tag, id_tag, text, icon]
            node_list.append("#".join(node_value))
        return node_list

    def to_dict(self):
        return Counter(self.nodes)

    def __init__(self, path):
        self.folder = path
        self.nodes = []
        self.ns = ""
        self.run()

    def run(self):
        for root_dir, dirs, files in os.walk(self.folder):
            for layout_file in files:
                if layout_file.endswith('.xml'):
                    full_name = os.path.join(root_dir, layout_file)
                    layout_nodes = self.get_layouts(full_name)
                    self.nodes.extend(layout_nodes)


class UIElements(luigi.Task):
    
    file_name = luigi.Parameter()

    def __init__(self, *args, **kwargs):
        super(UIElements, self).__init__(*args, **kwargs)
        self.pkg, self.vercode, self.date = commons().get_apk_data(self.file_name)

    # requires json of single releases
    def requires(self):
        return ApktoolRun(file_name=self.file_name)

    def output(self):
        output_file = os.path.join(cfg.apktool_ui_folder,
                                   self.pkg,
                                   self.pkg + "_" +
                                   self.vercode + "_" +
                                   self.date + ".json")
        return ExternalFileTarget(output_file)

    def run(self):
        # create output directory if missing
        if not os.path.isdir(os.path.dirname(self.output().path)):
            os.makedirs(os.path.dirname(self.output().path))
        apk_dir = self.input().path.replace(".json", ".out")
        check_unzip_layout_folder(self.input().path, apk_dir)
        layouts_folder = os.path.join(apk_dir, "res", "layout")
        layouts = Layouts(layouts_folder)
        res = layouts.to_dict()

        self.input().cleanup()
        
        with self.output().open('w') as f:
            json.dump(res, f)


class UICompare(luigi.Task):
    apks = luigi.ListParameter()
    pkg = luigi.Parameter()

    # requires json of single releases
    def requires(self):
        return [UIElements(file_name=apk) for apk in self.apks]

    # output is the json file with aggregated info of the app
    def output(self):
        output_file = os.path.join(cfg.apktool_ui_diff_folder,
                                   self.pkg,
                                   self.pkg + ".json")
        return ExternalFileTarget(output_file)

    def atoi(self, text):
        return int(text) if text.isdigit() else text

    def natural_keys(self, text):
        return [self.atoi(c) for c in re.split('(\d+)', text)]

    # creates the json application file
    def run(self):
        out_json = []
        ui_diff = {}
        for i in self.input():
            out_json.append(i.path)
        out_json.sort(key=self.natural_keys)
        for i in range(len(out_json) - 1):
            next_version = out_json[i + 1].split("_")[-2]
            out_diff = self.do_ui_comparison(out_json[i], out_json[i + 1])
            ui_diff[next_version] = out_diff

        for i in self.input():
            i.cleanup()

        with self.output().open('w') as f:
            json.dump(ui_diff, f, sort_keys=True)

    def do_ui_comparison(self, v_old, v_new):
        with open(v_old, "r") as v_old_f, open(v_new, "r") as v_new_f:
            old_layouts_dict = json.load(v_old_f)
            new_layouts_dict = json.load(v_new_f)
        deleted_items = set(old_layouts_dict.keys()) - set(new_layouts_dict.keys())
        new_items = set(new_layouts_dict.keys()) - set(old_layouts_dict.keys())
        updated_items = set(old_layouts_dict.keys()) & set(new_layouts_dict.keys())
        for item in updated_items:
            delta = old_layouts_dict[item] - new_layouts_dict[item]
            if delta > 0:
                deleted_items.add(item)
            elif delta < 0:
                new_items.add(item)

        return {'deleted': len(deleted_items), 'added': len(new_items),
                "old_files": sum(old_layouts_dict.values())}


class UIMatrix(luigi.Task):
    apks = luigi.ListParameter()
    pkg = luigi.Parameter()

    def requires(self):
        return UICompare(pkg=self.pkg, apks=self.apks)

    def output(self):
        output_file = os.path.join(cfg.apktool_ui_matrix_folder,
                                   self.pkg,
                                   self.pkg + ".json")
        return ExternalFileTarget(output_file)

    def get_matrix(self, app):
        ylabels = []
        for apk in app['apks']:
            for data in apk['data'].keys():
                if data not in ylabels:
                    ylabels.append(data)
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

    def run(self):
        app = {'pkg': self.pkg, 'apks': []}
        with self.input().open('r') as data_file:
            ui_diff = json.load(data_file)
            for version, data in ui_diff.items():
                apk = {}
                apk['vercode'] = version
                apk_data = {}
                apk_data['ui_added'] = float(data['added']) / data['old_files'] if data['old_files'] > 0 else -1
                apk_data['ui_deleted'] = float(data['deleted']) / data['old_files'] if data['old_files'] > 0 else -1
                apk['data'] = apk_data
                app['apks'].append(apk)
        app['apks'] = sorted(app['apks'], key=lambda k: int(k['vercode']))
        matrix, ylabels, xlabels = self.get_matrix(app)
        data = {'m': matrix.tolist(),
                'yl': ylabels,
                'xl': xlabels}
        with self.output().open('w') as data_file:
            json.dump(data, data_file)


class UIHeatmap(luigi.Task):
    apks = luigi.ListParameter()
    pkg = luigi.Parameter()
    app_info_folder = cfg.info_app_folder

    def requires(self):
        appinfo_file = os.path.join(self.app_info_folder,
                                    self.pkg,
                                    self.pkg + '.json')

        return {'matrix': UIMatrix(pkg=self.pkg, apks=self.apks),
                'apktool_matrix': ApktoolMatrix(pkg=self.pkg, apks=self.apks),
                'app_info': ExternalFile(file_name=appinfo_file)}

    def output(self):
        output_file = os.path.join(cfg.apktool_ui_heatmap_folder,
                                   self.pkg + ".pdf")
        return ExternalFileTarget(output_file)

    def get_app_info(self):
        with self.input()['app_info'].open() as data_file:
            return json.load(data_file)

    def create_heatmap(self, data):
        sorted_labels = ['ui_added', 'ui_deleted', 'changed', 'added', 'removed', 'modification', 'insertion',
                         'deletion',
                         'drawable', 'values', 'smali']
        data.index.name = "ui"
        data.columns.name = "Versions"
        app_info = self.get_app_info()
        col_labels = data.columns
        col_colors = heatmaps.get_col_colors(col_labels, app_info)
        vmax = data.values.max()
        splot = heatmaps.plot_heatmap(data, vmax=vmax, sorted_labels=sorted_labels, col_colors=col_colors)
        splot.ax_heatmap.hlines([2, 5, 8, 10], *splot.ax_heatmap.get_xlim(), linewidth=0.5, linestyle='dotted')
        
        # create output folder if it does not exist
        if not os.path.exists(os.path.dirname(self.output().path)):
            os.makedirs(os.path.dirname(self.output().path))
        splot.savefig(os.path.abspath(self.output().path), format='pdf')

    def run(self):
        # create output directory if missing
        if not os.path.isdir(os.path.dirname(self.output().path)):
            os.makedirs(os.path.dirname(self.output().path))

        with open(self.input()['matrix'].path) as data_file:
            data = json.load(data_file)
        with open(self.input()['apktool_matrix'].path) as data_file:
            layout_data = json.load(data_file)
        all_data = pd.DataFrame(100 * numpy.array(data['m']), index=data['yl'], columns=data['xl'])
        l_data = pd.DataFrame(100 * numpy.array(layout_data['m']), index=layout_data['yl'], columns=layout_data['xl'])
        all_data = all_data.append(l_data)
        matrix = all_data
        # data['yl'] + layout_data['yl'], data['xl'] + layout_data['xl'])
        self.create_heatmap(matrix)


''' WrapperTask to analyze Apktool all apks in the apks folder '''


class AllTaskAnalysis(luigi.WrapperTask):

    r = luigi.Parameter(default="")
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
            if self.r == 'apiperm':
                yield ExtractPermissionApi(pkg=pkg, apks=apks)
            elif self.r == 'smali':
                yield SmaliList(pkg=pkg, apks=apks)
            elif self.r == 'manifest':
                yield ManifestHeatmap(pkg=pkg, apks=apks)
            elif self.r == 'apktool_only':
                yield [ApktoolRun(file_name=apk) for apk in apks]
            elif self.r == 'apk':
                yield ApktoolHeatmap(pkg=pkg, apks=apks)
            elif self.r == 'ui':
                yield UIHeatmap(pkg=pkg, apks=apks)
            elif self.r == 'apidiff':
                yield APIDiff(pkg=pkg, apks=apks)
            elif self.r == 'perm_api':
                yield ExtractPermissionApi(pkg=pkg, apks=apks)
            elif self.r == 'api_loc':
                yield ExtractApiLocation(pkg=pkg, apks=apks)
            elif self.r == 'evo':
                # yields tasks necessary for perm evolution analysis (apis)
                yield ExtractApiLocation(pkg=pkg, apks=apks)
                yield SmaliList(pkg=pkg, apks=apks)
            else:
                print('Error: incorrect phase', self.r)


if __name__ == '__main__':
    luigi.run(main_task_cls=AllTaskAnalysis)
