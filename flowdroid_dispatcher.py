import csv
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from itertools import dropwhile

import luigi
import matplotlib
import xmltodict

import cfg
import lib_utils
from targets import ExternalFileTarget, ApkFile, ExternalFile

matplotlib.use('Agg')

sys.path.append("..")
from commons import commons
from constants import CONTENT_RESOLVER_CAT

permission_mapping_file = commons().permission_mapping
permission_mapping = [line.rstrip('\n').split(';')[0].strip('<>') for line in open(permission_mapping_file)]

OBFUSCATED_ITEM_SIZE = 2
PACKAGE_PREFIX_MIN_SIZE = 8
PACKAGE_PREFIX_MIN_PARTS = 2
OBFUSCATED_TAG = 'obfuscated'
APPCODE_TAG = 'appcode'


# noinspection PyStatementEffect
class Statement(object):
    ip_pattern = re.compile("(https?://)?[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")
    url_pattern = re.compile(
        r'"(?:(?:https?|ftp)://)?(?:\S+(?::\S*)?@)?(?:(?:(?:[a-z\\x{00a1}\-\\x{ffff}0-9]+-?)*[a-z\\x{00a1}\-\\x{ffff}0-9]+)(?:\.(?:[a-z\\x{00a1}\-\\x{ffff}0-9]+-?)*[a-z\\x{00a1}\-\\x{ffff}0-9]+)*(?:\.(?:[a-z\\x{00a1}\-\\x{ffff}]{2,})))(?::\d{2,5})?(?:/[^\s]*)?"')
    file_pattern = re.compile(r'"(/[a-z_\-0-9.]+)+"')
    content_pattern = re.compile(r'"(?i)content:/(/[a-z0-9.]+)+"')
    content_uri_pattern = re.compile(r'.*CONTENT_.*URI.*')

    def __init__(self, statement, method, value=""):
        self.stmt = self.unescape(statement)
        self.method = self.unescape(method)
        if self.is_content():
            self.name = self.content_pattern.search(self.stmt).group(0) if self.content_pattern.search(
                self.stmt) else self.content_uri_pattern.search(self.stmt).group(
                0)  # FIXME: we miss content_uri_pattern here
        else:
            self.name = self.get_content(self.stmt)
        if value != "":  # value is not empty if it's a string (url or file name)
            self.name = self.unescape(value)
        self.value = value
        self.loc = self.get_location_from_method(self.method)

    def __hash__(self):
        return hash(str(self))

    @staticmethod
    def unescape(s):
        s = s.replace("&amp;", "&")
        s = s.replace("&lt;", "<")
        s = s.replace("&gt;", ">")
        s = s.replace("&quot;", '"')
        return s

    @staticmethod
    def get_content(statement):
        if re.search('<.*>', statement) is not None:
            return re.search('<(.*)>', statement).group(1)
        elif re.search('@parameter[0-9]*: (.*)', statement) is not None:
            return re.search('@parameter[0-9]*: (.*)', statement).group(1)
        else:
            return statement

    @staticmethod
    def get_location_from_method(method):
        rs = re.search("<([^:]+): [^ ]+ ([^(]+)", method)
        res = rs.group(1) + '.' + rs.group(2)
        # res = rs.group(1).replace(".", "/") + '.' + rs.group(2)
        return res

    def __eq__(self, other):
        return self.stmt == other.stmt and self.method == other.method

    def is_query(self):  # FIXME: refactor, rename, now it's quick fix to support content res
        content_res = [": android.database.Cursor query(", "ContentResolver: android.net.Uri insert(",
                       "ContentResolver: int insert(", "ContentResolver: int update("]
        for cr in content_res:
            if cr in self.stmt:
                return True
        return False

    def is_url(self):
        return self.url_pattern.search(self.stmt) is not None or self.ip_pattern.search(self.stmt) is not None

    def is_file(self):
        return self.file_pattern.search(self.stmt) is not None

    def is_content(self):
        return self.content_pattern.search(self.stmt) is not None or self.content_uri_pattern.search(
            self.stmt) is not None

    def set_file(self):
        if self.file_pattern.search(self.stmt):
            self.value = self.file_pattern.search(self.stmt).group()

    def set_url(self):
        if self.url_pattern.search(self.stmt):
            self.value = self.url_pattern.search(self.stmt).group()
        elif self.ip_pattern.search(self.stmt):
            self.value = self.url_pattern.search(self.stmt).group()


class Source(Statement):
    def is_normal_source(self):
        return self.name in permission_mapping


class Sink(Statement):
    def is_normal_sink(self):
        return self.name in permission_mapping


class DataFlow:
    logger = logging.getLogger("flowdroid.flow")

    def __init__(self, source, sink, path):
        self.source = source
        self.sink = sink
        self.taint_path = self.parse_path(path)
        content = source.is_content()
        if source.is_normal_source():
            self.type = 'normal'
        elif content:
            if sink.is_query():
                self.type = 'content'
            else:
                if self.has_query(self.taint_path):
                    self.type = 'normal'
                else:
                    self.type = 'content_noq'
        elif self.source.is_url():
            self.type = 'url'
            self.source.set_url()
        elif self.source.is_file():
            self.type = 'file'
            self.source.set_file()
        else:
            self.type = 'unknown'
            self.logger.error('Unknown flow type: {}'.format(source.stmt))
            # raise ValueError('Unknown flow type: {}'.format(source.stmt))  # FIXME: use mapping from source-sink

    @staticmethod
    def parse_path(path):
        chain = []
        for path_element in path:
            stmt = Statement(path_element["@Statement"], path_element["@Method"])
            chain.append(stmt)
        return chain

    @staticmethod
    def has_query(taint_path):
        is_query = False
        it = iter(taint_path)
        next(it)  # don't take source
        for stmt in it:
            is_query = is_query or stmt.is_query()
        return is_query

    def common_path(self, other_flows):
        max_len = 0
        target = None
        for flow in other_flows:
            path_len = 1
            for i in range(1, min(len(self.taint_path), len(flow.taint_path))):
                if self.taint_path[-i] == flow.taint_path[-i]:
                    path_len = i
                else:
                    break
            if path_len > max_len:
                max_len = path_len
                target = flow.source
        return target


class FlowDroidRun(luigi.Task):
    file_name = luigi.Parameter()

    flowdroid_folder = luigi.Parameter(significant=False)
    flowdroid_java_cmd = luigi.Parameter(significant=False)
    flowdroid_options = luigi.Parameter(significant=False)
    flowdroid_extra_options = luigi.Parameter(default="", significant=False)
    flowdroid_sourcessinks = luigi.ListParameter(default=[], significant=False)
    timeout_cmd = luigi.Parameter(significant=False)
    android_platform = luigi.Parameter(significant=False)
    flow_run_folder = luigi.Parameter(default=cfg.flow_run_folder, significant=False)

    def __init__(self, *args, **kwargs):
        super(FlowDroidRun, self).__init__(*args, **kwargs)
        self.pkg, self.vercode, self.date = commons().get_apk_data(self.file_name)

    resources = {'big_ram-{}'.format(commons().hostname): 1}

    @staticmethod
    def escape(s):
        s = s.replace("&", "&amp;")
        s = s.replace("<", "&lt;")
        s = s.replace(">", "&gt;")
        s = s.replace('"', "&quot;")
        return s

    def requires(self):  # TODO: think of better dependencies
        return ApkFile(file_name=self.file_name)  # , 'sources': sources}

    def output(self):
        res_file = os.path.join(self.flow_run_folder, self.pkg, self.file_name + ".xml")
        log_file = os.path.join(self.flow_run_folder, self.pkg, self.file_name + "_log.txt")
        return {'flows': ExternalFileTarget(res_file), 'log': ExternalFileTarget(log_file)}

    def create_sources_sinks(self, ss_mapping):
        # write source and sink mapping to file
        ss_tmp_file = os.path.join(tempfile.gettempdir(), 'flowdroid-ss-tmp-{}.txt'.format(self.file_name))
        with open(ss_tmp_file, 'w') as data_file:
            data_file.write('\n'.join(ss_mapping))
        return ss_tmp_file

    def get_sources_sinks_file(self, ss_mapping):
        # noinspection PyTypeChecker
        if len(self.flowdroid_sourcessinks) > 0:
            return self.create_sources_sinks(ss_mapping)
        else:
            raise Exception('empty sourcessinks')

    def cleanup(self, f_name_list):
        self.input().cleanup()
        for f_name in f_name_list:
            try:
                os.remove(f_name)
            except OSError:
                pass

    def run(self):
        logger = logging.getLogger("flowdroid")
        logger.info('Running FlowDroid on apk ' + self.file_name)
        # preparing the command to run:
        cd_cmd = 'cd {};'.format(self.flowdroid_folder)
        sourcessinks_file = self.get_sources_sinks_file(self.flowdroid_sourcessinks)
        flowdroid_sourcessinks = "--sourcessinks {}".format(sourcessinks_file)
        res_tmp_file = os.path.join(tempfile.gettempdir(), 'flowdroid-tmp-{}.xml'.format(self.file_name))
        cmd = '{cd} {time} {fl_cp} "{apk}" {android} {fl_opt} {fl_ss} {fl_extra} --saveresults {res}'.format(cd=cd_cmd,
                                                                                                             time=self.timeout_cmd,
                                                                                                             fl_cp=self.flowdroid_java_cmd,
                                                                                                             apk=self.input().path,
                                                                                                             android=self.android_platform,
                                                                                                             fl_opt=self.flowdroid_options,
                                                                                                             fl_ss=flowdroid_sourcessinks,
                                                                                                             fl_extra=self.flowdroid_extra_options,
                                                                                                             res=res_tmp_file)
        curr_time = time.time()
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        logger.debug('Running flowdroid command: ' + cmd)
        output, err = process.communicate()
        output = output.decode('utf-8')
        err = err.decode('utf-8')
        proc_runtime = str(int(time.time() - curr_time))
        with self.output()['log'].open('w') as ll:
            ll.write('Cmd: {}\n'.format(cmd))
            ll.write('Processing time: {}\n'.format(proc_runtime))
            ll.write('******OUT*******\n')
            ll.write(output + '\n')
            ll.write('******ERR*******\n')
            ll.write(err)

        logger.debug('FlowDroid error: ' + err)
        logger.debug('FlowDroid out: ' + output)
        status = process.returncode
        # if status is 124 a timeout occurred: create output file with TIMEOUT
        # error
        xml_output_template = \
            '''<?xml version="1.0" ?>
            <DataFlowResults FileFormatVersion="100">
            <error>{err_msg}</error>
            </DataFlowResults>
            '''
        if status == 124:
            with self.output()['flows'].open('w') as f:
                # write xml with error flag for TIMEOUT
                xml_output = xml_output_template.format(err_msg="TIMEOUT")
                f.write(xml_output)
            return
        if status != 0:  # makes the task fail
            raise Exception('Flowdroid failed to run')
        # if output file does not exist an error occurred:
        # create output file with error log
        if not os.path.isfile(res_tmp_file):
            with self.output()['flows'].open('w') as f:
                err_msg = re.findall(r'Exception:? .*', err)
                if err_msg:
                    err_msg = self.escape(err_msg[0])
                else:
                    err_msg = "Unknown"
                xml_output = xml_output_template.format(err_msg=err_msg)
                f.write(xml_output)
        else:
            with open(res_tmp_file, 'r') as src_f, self.output()['flows'].open('w') as dest_f:
                dest_f.write(src_f.read())
        # cleaning up local tmp files
        to_remove = [res_tmp_file]
        # noinspection PyTypeChecker
        if len(self.flowdroid_sourcessinks) > 0:
            to_remove.append(sourcessinks_file)

        self.cleanup(to_remove)


# combines flows
class FlowDroidJson(FlowDroidRun):
    file_name = luigi.Parameter()
    flow_json_folder = luigi.Parameter(default=cfg.flow_json_folder, significant=False)

    def __init__(self, *args, **kwargs):
        super(FlowDroidJson, self).__init__(*args, **kwargs)
        self.pkg, self.vercode, self.date = commons().get_apk_data(self.file_name)
        self.main_xml = None
        self.flows = []
        self.error = None
        self.incomplete = False

    def requires(self):
        common_params = list(set.intersection(set(FlowDroidRun.get_params()), set(self.get_params())))
        common_kwargs = dict([(key, self.param_kwargs[key]) for key in dict(common_params).keys()])
        vals = dict(self.get_param_values(common_params, [], common_kwargs))
        return FlowDroidRun(file_name=self.file_name, **vals)

    def output(self):
        output_file = os.path.join(self.flow_json_folder, self.pkg,
                                   self.file_name + ".json")
        return ExternalFileTarget(output_file)

    def parse_xml(self):
        with self.input()['flows'].open() as fd:
            self.main_xml = xmltodict.parse(fd.read(), force_list=['Source', 'Sink', 'Result'])
        # if an error occured, add an "error" key.
        if 'error' in self.main_xml["DataFlowResults"]:
            self.error = self.main_xml["DataFlowResults"]['error']
        # if there is "no results", set "ss" empty.
        elif self.main_xml["DataFlowResults"]['Results'] is not None:
            # get all data flows from tag "Result"
            results = self.main_xml["DataFlowResults"]['Results']['Result']
            # if isinstance(results, dict):
            #     results = [results]
            for result in results:
                # process the sink
                for sink_tag in result['Sink']:
                    value = sink_tag.get('Value', "")
                    sink = Sink(sink_tag["@Statement"], sink_tag["@Method"], value=value)
                    # process the source
                    sources = result['Sources']['Source']
                    # if isinstance(sources, dict):
                    #     sources = [sources]
                    for s in sources:
                        value = s.get('Value', "")
                        source = Source(s["@Statement"], s["@Method"], value=value)
                        taint_path = s['TaintPath']['PathElement']
                        flow = DataFlow(source, sink, taint_path)
                        self.flows.append(flow)
        log_file = self.input()['log']
        if self.is_timeout(log_file):
            self.incomplete = True

    @staticmethod
    def is_timeout(log_file):
        with log_file.open() as lf:
            lines = lf.read()
            # for line in lf.read().splitlines():
            return "Timeout reached, stopping the solvers." in lines  # FIXME: check if this is the right message

    def make_ref_table(self):
        ref_table = defaultdict(list)
        for flow in self.flows:
            if flow.type == 'file' or flow.type == 'url':
                ref_table[flow.sink].append(flow)
        return ref_table

    def make_content_table(self):
        ref_table = dict()
        for flow in self.flows:
            if flow.type == 'content':
                ref_table[flow.sink] = flow
        return ref_table

    def parse_flows(self):
        apk_dict = {}
        ss = list()
        apk_dict['pkg'] = self.pkg
        apk_dict['vercode'] = self.vercode
        apk_dict['date'] = self.date
        self.parse_xml()  # FIXME: add error handling
        ref_table = self.make_ref_table()
        content_table = self.make_content_table()
        # if an error occured, add an "error" key.
        if self.error:
            apk_dict['error'] = self.error
        # TODO: describe logic
        for flow in self.flows:
            sink_name = flow.sink.name
            source_name = flow.source.name
            if flow.type == 'normal':
                if flow.sink in ref_table:  # resolve_flows
                    sink = flow.common_path(ref_table[flow.sink])
                    sink_name = sink.name + sink.value
                if flow.source in content_table:
                    source = content_table.get(flow.source).source
                    source_name = source.name + source.value
                sink_location = flow.sink.loc
                sspair = dict()
                sspair['sink'] = {'name': sink_name, 'loc': sink_location}
                source_location = flow.source.loc
                sspair['source'] = {'name': source_name, 'loc': source_location}
                ss.append(sspair)
            if flow.type == 'content':  # FIXME it's quick fix to extract content res strings, refactor
                sspair = dict()
                sink_location = flow.sink.loc
                sspair['sink'] = {'name': sink_name, 'loc': sink_location}
                source_location = flow.source.loc
                sspair['source'] = {'name': source_name, 'loc': source_location}
                ss.append(sspair)

        apk_dict['ss'] = ss
        if self.incomplete:
            apk_dict['incomplete'] = True
        return apk_dict

    def run(self):
        apk_dict = self.parse_flows()
        with self.output().open('w') as f:
            json.dump(apk_dict, f, indent=1)


class AggregateFlows(luigi.Task):
    apks = luigi.ListParameter(significant=False)
    pkg = luigi.Parameter()

    # requires json of single releases
    def requires(self):
        # noinspection PyTypeChecker
        return [FlowDroidJson(file_name=apk) for apk in self.apks]

    # output is the json file with aggregated info of the app
    def output(self):
        output_file = os.path.join(cfg.flow_aggregated_json_folder,
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
            json.dump(app, f, indent=1)


# ##refactored until here#########

# Task to create the application json, containing all json of single releases
class AppFlow(luigi.Task):
    apks = luigi.TupleParameter(significant=False)
    pkg = luigi.Parameter()
    perm_mapping = luigi.Parameter()

    # requires json of single releases
    def requires(self):
        info_path = os.path.join(cfg.info_app_folder,
                                 self.pkg, self.pkg + ".json")
        libs_path = os.path.join(cfg.libradar_pkglibrary_folder, self.pkg, self.pkg + ".json")

        return {'flow_tasks': AggregateFlows(pkg=self.pkg, apks=self.apks),
                'app_info': ExternalFile(file_name=info_path),
                'libs': ExternalFile(file_name=libs_path)}

    # output is the json file with aggregated info of the app
    def output(self):
        output_file = os.path.join(cfg.flow_appflow_folder,
                                   self.pkg,
                                   self.pkg + ".json")
        return ExternalFileTarget(output_file)

    @staticmethod
    def csv_file_to_dict(filename):
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
        lp = lib_utils.LibProvider(libs_fd, lib_names=True, unknown_libs=True, apk_info_fd=info_fd,
                                   unknown_lib_loc=False)
        categories = commons().csv_file_to_dict(self.perm_mapping)
        # for each release, add json data to app dict
        with self.input()['flow_tasks'].open() as data_file:
            data = json.load(data_file)
            for apk in data['apks']:
                vercode = apk['vercode']
                ssdict = defaultdict(int)
                for flow in apk['ss']:
                    sink_name = '<' + flow['sink']['name'] + '>'
                    if sink_name in categories:
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


# FIXME: what is the purpose of this task? weird output
class FlowDroidContentRes(luigi.Task):
    """
    Task for extracting content resolver data flows
    """
    pkg = luigi.Parameter()
    apks = luigi.ListParameter(significant=False)
    flow_json_folder = cfg.soot_flowdroid_json_folder
    flow_run_folder = cfg.soot_flowdroid_run_folder
    flowdroid_sourcessinks = luigi.Parameter(significant=False)

    def __init__(self, *args, **kwargs):
        super(FlowDroidContentRes, self).__init__(*args, **kwargs)

    def requires(self):
        flowdroid_sourcessinks_file = os.path.abspath(self.flowdroid_sourcessinks)
        with open(flowdroid_sourcessinks_file) as fd:
            ss_mapping = [x.strip('\n') for x in fd.readlines()]
        flowdroid_extra_options = '--contentsources'
        for file_name in self.apks:
            yield FlowDroidJson(file_name=file_name, flowdroid_sourcessinks=ss_mapping,
                                flowdroid_extra_options=flowdroid_extra_options,
                                flow_json_folder=self.flow_json_folder, flow_run_folder=self.flow_run_folder)

    def output(self):
        output_file = os.path.join(cfg.soot_flowdroid_content_folder,
                                   self.pkg,
                                   self.pkg + ".json")
        return ExternalFileTarget(output_file)

    @staticmethod
    def get_pkg_prefix(pkg):  # FIXME: refactor, use method from lib_utils
        it = iter(pkg.split('.'))
        pkg_prefix = next(it)
        count = 1
        for part in it:
            if len(pkg_prefix) >= PACKAGE_PREFIX_MIN_SIZE + count - 1 and count >= PACKAGE_PREFIX_MIN_PARTS:
                break
            pkg_prefix = pkg_prefix + '.' + part
            count += 1
        return pkg_prefix

    @staticmethod
    def transform_obfuscated(loc):  # FIXME: refactor, use method from lib_utils
        return '.'.join(reversed(list(dropwhile(lambda x: len(x) < OBFUSCATED_ITEM_SIZE, reversed(loc.split('.'))))))

    @staticmethod
    def transform_appcode(loc, prefix):  # FIXME: refactor, use method from lib_utils
        tloc = loc + '.'
        if tloc.startswith(prefix + '.'):
            return APPCODE_TAG
        else:
            return loc

    @staticmethod
    def strip_class_name(loc):  # FIXME: refactor, use method from lib_utils
        idx = loc.rfind('.')
        if idx > 0:
            return loc[:idx]
        else:
            return OBFUSCATED_TAG

    @staticmethod
    def transform_uri(content_uri):
        content_uri = content_uri.strip('"')
        if 'CONTENT_URI' in content_uri:
            content_uri_re = re.search("([^\s<]+): [^\s]+ ([^\s>]+)", content_uri)
            content_uri = '{}.{}'.format(content_uri_re.group(1), content_uri_re.group(2))
            content_uri.replace('$', '.')
        else:
            content_uri_parts = content_uri.replace('content://', '').split('/')
            content_uri = 'content://{}'.format(content_uri_parts[0])
        return content_uri

    @staticmethod
    def is_sensitive_uri(content_uri):
        return content_uri in CONTENT_RESOLVER_CAT

    def get_content_api(self, content):
        api_res = dict()
        apis = defaultdict(list)
        vercode = content['vercode']
        flows = content['ss']
        pkg = content['pkg']
        pkg_prefix = self.get_pkg_prefix(pkg)
        for flow in flows:
            content_uri = flow['source']['name']
            content_uri = self.transform_uri(content_uri)
            if not self.is_sensitive_uri(content_uri):
                continue
            sink_name = flow['sink']['name']
            loc = flow['sink']['loc']
            loc = self.strip_class_name(loc)
            loc = self.transform_obfuscated(loc)
            loc = self.transform_appcode(loc, pkg_prefix)
            api = '<{}>{{{}}}'.format(sink_name, content_uri)
            apis[api].append(loc)
        api_res[vercode] = apis
        return api_res

    def run(self):
        # app = {'pkg': self.pkg, 'apks': []}
        # for each release, add json data to app dict
        app = dict()
        for i in self.input():
            with i.open() as data_file:
                content = json.load(data_file)
                apis = self.get_content_api(content)
                app.update(apis)
        # sort apks list according to version code
        # app['apks'] = sorted(app['apks'], key=lambda k: int(k['vercode']))
        with self.output().open('w') as f:
            json.dump(app, f, indent=2)


''' Commented code for legacy tasks. Review before deteting it '''
# # Task to create the heatmap matrix
# class AppFlowMatrix(luigi.Task):
#     apks = luigi.TupleParameter()
#     pkg = luigi.Parameter()
#
#     # requires application json
#     def requires(self):
#         return {'json': AppFlow(pkg=self.pkg, apks=self.apks)}
#
#     # output is the matrix json file
#     def output(self):
#         output_file = os.path.join(cfg.flow_appflow_matrix_folder,
#                                    self.pkg,
#                                    self.pkg + ".json")
#         return ExternalFileTarget(output_file)
#
#     # returns a matrix with source-sink pairs on the y-axis
#     # and version on the x-axis
#     def get_matrix(self, app):
#         # get all source-sink combinations as y-labels
#         ylabels = []
#         for apk in app['apks']:
#             for k, v in apk['ss'].items():
#                 if k not in ylabels:
#                     if 'LOG' not in k:  # exclude logs from heatmap
#                         ylabels.append(k)
#         ylabels.sort()
#
#         if len(ylabels) == 0:
#             ylabels.append('No flows')
#
#         matrix = numpy.zeros(shape=(len(app['apks']), len(ylabels)))
#         xlabels = []
#
#         # err_value is used to color versions for which flowdroid crashed
#         err_value = -1
#
#         for i in range(0, len(app['apks'])):
#             default_value = 0
#             apk = app['apks'][i]
#             xlabels.append(apk['vercode'])
#             values = []
#
#             # if flowdroid crashed set matrix to error
#             if 'error' in apk:
#                 default_value = err_value
#
#             for el in ylabels:
#                 if el in apk['ss'].keys():
#                     values.append(numpy.log(1 + apk['ss'][el]))
#                 else:
#                     values.append(default_value)
#             matrix[i] = values
#
#         return matrix.T, ylabels, xlabels
#
#     # creates the matrix
#     def run(self):
#         # create app dictionary
#
#         app = None
#         with open(self.input()['json'].path) as data_file:
#             app = json.load(data_file)
#
#         # get matrix and row/col labels
#         matrix, ylabels, xlabels = self.get_matrix(app)
#         data = {'m': matrix.tolist(),
#                 'yl': ylabels,
#                 'xl': xlabels}
#
#         # write matrix to json file
#         with self.output().open('w') as data_file:
#             json.dump(data, data_file)


# # Task to create the heatmap matrix
# class AppFlowBaseMatrix(luigi.Task):
#     apks = luigi.TupleParameter()
#     pkg = luigi.Parameter()
#     output_folder = cfg.flow_appflow_base_matrix_folder
#
#     # requires application json
#     def requires(self):
#         return {'json': AppFlow(pkg=self.pkg, apks=self.apks)}
#
#     # output is the matrix json file
#     def output(self):
#         output_file = os.path.join(self.output_folder,
#                                    self.pkg,
#                                    self.pkg + ".json")
#         return luigi.LocalTarget(output_file)
#
#     # returns a matrix with source-sink pairs on the y-axis
#     # and version on the x-axis
#     def get_matrix(self, app):
#         # get all source-sink combinations as y-labels
#         ylabels = []
#         for apk in app['apks']:
#             for k, v in apk['ss'].items():
#                 if k not in ylabels:
#                     if ' - LOG' not in k:  # exclude logs from heatmap
#                         ylabels.append(k)
#         ylabels.sort()
#
#         if len(ylabels) == 0:
#             ylabels.append('No flows')
#
#         matrix = numpy.zeros(shape=(len(app['apks']), len(ylabels)))
#         xlabels = []
#
#         # err_value is used to color versions for which flowdroid crashed
#         err_value = -1
#
#         for i in range(0, len(app['apks'])):
#             default_value = 0
#             apk = app['apks'][i]
#             xlabels.append(apk['vercode'])
#             values = []
#
#             # if flowdroid crashed set matrix to error
#             if 'error' in apk:
#                 default_value = err_value
#
#             for el in ylabels:
#                 if el in apk['ss'].keys():
#                     values.append(apk['ss'][el])
#                 else:
#                     values.append(default_value)
#             matrix[i] = values
#
#         return matrix.T, ylabels, xlabels
#
#     # creates the matrix
#     def run(self):
#         # create app dictionary
#
#         app = None
#         with open(self.input()['json'].path) as data_file:
#             app = json.load(data_file)
#
#         # get matrix and row/col labels
#         matrix, ylabels, xlabels = self.get_matrix(app)
#         data = {'m': matrix.tolist(),
#                 'yl': ylabels,
#                 'xl': xlabels}
#
#         # write matrix to json file
#         with self.output().open('w') as data_file:
#             json.dump(data, data_file)


# # Task to create the application json, containing all json of single releases
# class AppFlowHeatmap(luigi.Task):
#     apks = luigi.TupleParameter()
#     pkg = luigi.Parameter()
#     output_folder = cfg.flow_appflow_heatmap_folder
#     app_info_folder = cfg.info_app_folder
#     app_flow_folder = cfg.flow_appflow_folder
#
#     # requires application json
#     def requires(self):
#         appinfo_file = os.path.join(self.app_info_folder,
#                                     self.pkg,
#                                     self.pkg + '.json')
#
#         # appflow_file = os.path.join(self.app_flow_folder,
#         #                             self.pkg,
#         #                             self.pkg + '.json')
#
#         return {'matrix': AppFlowMatrix(pkg=self.pkg, apks=self.apks),
#                 'app_info': ExternalFile(apk_file=appinfo_file),
#                 'app_flow': AppFlow(pkg=self.pkg, apks=self.apks)}
#
#     # output is the heatmap
#     def output(self):
#         output_file = os.path.join(self.output_folder,
#                                    self.pkg + ".pdf")
#         return luigi.LocalTarget(output_file)
#
#     def get_col_colors_versions(self, col_labels, app_info):
#         # initializing col_colors, the first column is always white
#         col_colors = ['white']
#
#         # for each column name we check if the version name is the same
#         # as the one of the previous version, in that case we put a red flag.
#         # if the versionName has a major change, we put a green flag
#         for i in range(1, len(col_labels)):
#             actual_vn = app_info[col_labels[i]]['versionName']
#             previous_vn = app_info[col_labels[i - 1]]['versionName']
#             if actual_vn == previous_vn:
#                 col_colors.append('red')
#                 continue
#
#             a_split = actual_vn.split('.')
#             p_split = previous_vn.split('.')
#
#             # if the versioning format changed use a yellow flag
#             if len(a_split) != len(p_split):
#                 col_colors.append('yellow')
#
#             # if the first part of version changed flag green
#             elif len(a_split) > 1 and a_split[0] != p_split[0]:
#                 col_colors.append('green')
#
#             # if there are at least 2 dots, if the second part of
#             # the version changes flag light green
#             elif len(a_split) > 2 and len(p_split) > 2 and a_split[1] != p_split[1]:
#                 col_colors.append('lightgreen')
#
#             # else use default color (white)
#             else:
#                 col_colors.append('white')
#
#         # return col_colors list just created
#         return col_colors
#
#     def get_col_colors_incomplete(self, app_flows):
#         col_colors = list()
#         for apk in app_flows['apks']:
#             if apk['incomplete']:
#                 col_colors.append('red')
#             else:
#                 col_colors.append('white')
#         return col_colors
#
#     def get_app_info(self):
#         appinfo_file = self.input()['app_info'].path
#         with open(appinfo_file) as data_file:
#             return json.load(data_file)
#
#     def get_app_flows(self):
#         appflow_file = self.input()['app_flow'].path
#         with open(appflow_file) as data_file:
#             return json.load(data_file)
#
#     # creates the heatmap of permission use and saves it to a file
#     def create_heatmap(self, data, row_labels, col_labels):
#         # create output directory if it does not exists (it is not
#         # automatically created by plt.savefig)
#         app_info = self.get_app_info()
#         app_flow = self.get_app_flows()
#         version_colors = self.get_col_colors_versions(col_labels, app_info)
#         incomplete_colors = self.get_col_colors_incomplete(app_flow)
#         col_colors = pd.DataFrame.from_dict({'versions': version_colors, 'incomplete': incomplete_colors})
#         pdata = pd.DataFrame(data, index=row_labels, columns=col_labels)
#         pdata.index.name = "dataflow"
#         pdata.columns.name = "Versions"
#         col_colors.index = pdata.columns
#
#         dpi = 72.27
#         fontsize_x_pt = 10
#         fontsize_y_pt = 10
#         col_labels_height = 0.66
#         col_label_size = col_colors.shape[0] * col_labels_height
#         # compute the matrix height in points and inches
#         matrix_height_pt = fontsize_y_pt * (data.shape[0] + col_label_size)
#         matrix_height_in = matrix_height_pt / dpi
#         matrix_width_pt = fontsize_x_pt * data.shape[1]
#         matrix_width_in = matrix_width_pt / dpi
#
#         top_margin = 0.04  # in percentage of the figure height
#         bottom_margin = 0.04  # in percentage of the figure height
#         coef = 2
#         figure_height = coef * matrix_height_in / (1 - top_margin - bottom_margin)
#         figure_width = coef * matrix_width_in / (1 - top_margin - bottom_margin)
#
#         cm = plt.cm.get_cmap('hot')  # cubehelix plasma viridis
#         cm = colors.LinearSegmentedColormap('gist_heat_r',
#                                             plt.cm.revcmap(cm._segmentdata))
#         # from http://seaborn.pydata.org/tutorial/color_palettes.html
#         # TODO: cm = sns.color_palette("cubehelix", 8, as_cmap=True)
#         # http://matplotlib.org/users/colormaps.html
#         cm.set_bad(color='blue')
#
#         # TODO put this in all heatmap creation. refactor code
#         row_cluster = True if data.shape[0] > 1 else False
#
#         splot = sns.clustermap(pdata, col_cluster=False, row_cluster=row_cluster,
#                                col_colors=col_colors,
#                                figsize=(figure_width, figure_height),
#                                # annot=True, annot_kws={'fontsize': 3}, # commented for konstantin's code
#                                cmap=cm, vmin=0, mask=(data == -1))
#         splot.cax.set_visible(False)
#
#         plt.setp(splot.ax_row_dendrogram, visible=False)
#         plt.setp(splot.ax_col_dendrogram, visible=False)
#         splot.ax_heatmap.yaxis.set_ticks_position('left')
#         splot.ax_heatmap.yaxis.set_label_position('left')
#         splot.ax_heatmap.set_xlabel(pdata.columns.name, fontsize=10)
#         splot.ax_heatmap.set_ylabel(pdata.index.name, fontsize=10)
#         # ax.ylabel('urls', fontsize=10)
#
#         splot.ax_heatmap.set_yticks(numpy.arange(data.shape[0]) + 0.5, minor=False)
#         plt.setp(splot.ax_heatmap.get_yticklabels(), rotation=0)
#         plt.setp(splot.ax_heatmap.get_xticklabels(), rotation=90)
#         plt.setp(splot.ax_heatmap.get_yticklabels(), fontsize=10)
#         plt.setp(splot.ax_heatmap.get_xticklabels(), fontsize=8)
#         with self.output().open('w') as fd:
#             splot.savefig(fd, format='pdf')
#
#     # creates the heatmap
#     def run(self):
#         # read app matrix from json
#         with self.input()['matrix'].open() as data_file:
#             data = json.load(data_file)
#
#         # get matrix and create the heatmap
#         matrix = numpy.array(data['m'])
#         self.create_heatmap(matrix, data['yl'], data['xl'])
#
#
# # WrapperTask to analyze with FlowDroid all apks in the apks folder
# # FIXME: use list as an input
# class InfoFlowAnalysis(luigi.WrapperTask):
#     apks_folder = cfg.apks_folder
#     apk_list = luigi.Parameter(default="")
#     exclude_apk_list = luigi.Parameter(default="")
#
#     def requires(self):
#         apps = defaultdict(set)
#         target_folders = [self.apks_folder]
#         if self.apk_list != "":
#             # noinspection PyTypeChecker
#             with open(self.apk_list, "r") as f:
#                 pkg_list = [x.strip() for x in f.readlines()]
#         else:
#             pkg_list = []
#         if self.exclude_apk_list != "":
#             # noinspection PyTypeChecker
#             with open(self.exclude_apk_list, "r") as f:
#                 exclude_pkg_list = [x.strip() for x in f.readlines()]
#         else:
#             exclude_pkg_list = []
#         for f in target_folders:
#             for root, dirs, files in os.walk(f):
#                 for basename in files:
#                     if basename.endswith('.apk'):
#                         pkg = "_".join(basename.split("_")[:-2])
#                         vercode = basename.split("_")[-2]
#                         date = basename.split("_")[-1].split('.')[0]
#                         apps[pkg].add((pkg, vercode, date))
#         if len(pkg_list) > 0:
#             apps = dict((key, value) for key, value in apps.items() if key in pkg_list)
#         if len(exclude_pkg_list) > 0:
#             for key in exclude_pkg_list:
#                 apps.pop(key, None)
#         for pkg, apks in apps.items():
#             yield AppFlowHeatmap(pkg=pkg, apks=apks)
#             yield AppFlowBaseMatrix(pkg=pkg, apks=apks)
#
#
# '''
# class ICAnalysis(luigi.WrapperTask):
#     apks_folder = luigi.Parameter()
#     apk_list = luigi.Parameter(default="")
#     exclude_apk_list = luigi.Parameter(default="")
#
#     def requires(self):
#         apps = defaultdict(set)
#         if self.apk_list != "":
#             with open(self.apk_list, "r") as f:
#                 pkg_list = [x.strip() for x in f.readlines()]
#         else:
#             pkg_list = []
#         if self.exclude_apk_list != "":
#             with open(self.exclude_apk_list, "r") as f:
#                 exclude_pkg_list = [x.strip() for x in f.readlines()]
#         else:
#             exclude_pkg_list = []
#         for root, dirs, files in os.walk(self.apks_folder):
#             for basename in files:
#                 if basename.endswith(('.apk', '.json', '.xml')):
#                     pkg = "_".join(basename.split("_")[:-2])
#                     vercode = basename.split("_")[-2]
#                     date = basename.split("_")[-1].split('.')[0]
#                     apps[pkg].add((pkg, vercode, date))
#         if len(pkg_list) > 0:
#             apps = dict((key, value) for key, value in apps.items() if key in pkg_list)
#         if len(exclude_pkg_list) > 0:
#             for key in apps.keys():
#                 if key in exclude_pkg_list:
#                     del apps[key]
#         for pkg, apks in apps.iteritems():
#             for apk in apks:
#                 yield ICRun(pkg=apk[0], vercode=apk[1], date=apk[2])
# '''