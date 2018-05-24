# coding=utf-8
import json
import logging

import luigi
import matplotlib

matplotlib.use('Agg')
import numpy
import os
import subprocess
import sys

sys.path.append("..")
import cfg
import domain_utils
import heatmaps
import lib_utils
import pandas as pd

from collections import defaultdict
from commons import commons
from targets import ExternalFileTarget, ApkFile, ExternalFile

logger = logging.getLogger('luigi-interface')

# python luigi_stringoid.py ApkUrlAnalysis --local-scheduler
# autopep8 luigi_stringoid.py --in-place


''' Runs stringoid on an apk '''


class StringoidRun(luigi.Task):
    file_name = luigi.Parameter()

    apks_folder = cfg.apks_folder
    stringoid_cmd = luigi.Parameter()

    def __init__(self, *args, **kwargs):
        super(StringoidRun, self).__init__(*args, **kwargs)
        self.pkg, self.vercode, self.date = commons().get_apk_data(self.file_name)

    # requires json of single releases
    def requires(self):
        return ApkFile(file_name=self.file_name)

    def output(self):
        stringoid_suffix = ".apk_constants_interproc"  # TODO extract from cmd line
        output_file = os.path.join(cfg.stringoid_run_folder,
                                   self.pkg,
                                   self.pkg + "_" +
                                   self.vercode + "_" +
                                   self.date + stringoid_suffix + ".json")
        return ExternalFileTarget(output_file)

    # create the json application file
    def run(self):

        # create output folder if it does not exist yet
        outfolder = os.path.join(os.path.dirname(self.output().path))
        if not os.path.isdir(outfolder):
            os.makedirs(outfolder)

        cmd = self.stringoid_cmd + " " + \
              self.input().path + " -o " + outfolder

        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        logger.debug('Running stringoid command: ' + cmd)
        output, err = process.communicate()
        #        logger.warning('Stringoid error: ' + err)
        logger.debug('Stringoid out: ' + str(output))

        # if output file does not exist an error occurred:
        # create output file with error message
        if not os.path.isfile(self.output().path):
            with self.output().open('w') as f:
                error_msg = {'stringoid_error': "STRINGOID CRASH"}
                json.dump(error_msg, f)


class StringoidParse(luigi.Task):
    """ Parse stringoid output to retrieve the domain for each found url """
    file_name = luigi.Parameter()

    def __init__(self, *args, **kwargs):
        super(StringoidParse, self).__init__(*args, **kwargs)
        self.pkg, self.vercode, self.date = commons().get_apk_data(self.file_name)

    # requires json of single releases
    def requires(self):
        return StringoidRun(file_name=self.file_name)

    def output(self):
        output_file = os.path.join(cfg.stringoid_parse_folder,
                                   self.pkg,
                                   self.pkg + "_" +
                                   self.vercode + "_" +
                                   self.date + ".json")
        return ExternalFileTarget(output_file)

    def run(self):

        is_error = False
        urls = dict()
        with open(self.input().path, "r") as f:
            url_data = json.load(f)
            if 'stringoid_error' in url_data.keys():
                is_error = True

            if "result" in url_data.keys():
                for url2method in url_data["result"]["url2methods"]:
                    methods = url2method["methods"]
                    for method in methods:
                        method = method.lstrip("L")
                        if isinstance(url2method["url"]["concat"], list):
                            for url in url2method["url"]["concat"]:
                                urls.update({url["value"]: method})
                        else:
                            urls.update(
                                {url2method["url"]["concat"]["value"]: method})

        if is_error:
            with self.output().open('w') as data_file:
                json.dump({'stringoid_error': 'STRINGOID CRASH'}, data_file)
                return

        domain_parser = domain_utils.DomainParser()
        cleaned_urls = {}

        # for each url, retrieve the domain; if it is not valid skip element
        for url, loc in urls.items():
            dom = domain_parser.clean_domain(url)
            if dom is not '':
                cleaned_urls[dom] = loc

        self.input().cleanup()
        with self.output().open('w') as f:
            json.dump(cleaned_urls, f, sort_keys=True)


class CommonDomains(luigi.Task):
    apks = luigi.TupleParameter()
    pkg = luigi.Parameter()
    domains_folder = cfg.dynamic_bro_analysis_folder

    def get_domains_file_path(self, version, date):
        return os.path.join(self.domains_folder,
                            self.pkg,
                            self.pkg + '_' + version + '_' + date,
                            'domains.txt')

    # requires json of single releases
    def requires(self):
        return [StringoidParse(file_name=apk) for apk in self.apks]

    # output is the json file with aggregated info of the app
    def output(self):
        output_file = os.path.join(cfg.stringoid_commondomains_folder,
                                   self.pkg + "_commondomains.json")
        return ExternalFileTarget(output_file)

    def run(self):
        commondomains = {}
        for i in self.input():
            domains_list = []
            both = []
            commondomain = {}
            with open(i.path) as url_file:
                urls = json.load(url_file)
                version = i.path.split("_")[-2]
                date = i.path.split("_")[-1].replace(".json", "")
                domains_path = self.get_domains_file_path(version, date)
                urls_list = urls.keys()
                with open(domains_path) as domain_file:
                    for line in domain_file:
                        domains_list.append(line.strip())
                        for url in urls.keys():
                            if line.strip() in url:
                                both.append(line.strip())
                                domains_list.remove(line.strip())
                                urls_list.remove(url)
                                break
            commondomain["domains"] = domains_list
            commondomain["urls"] = urls_list
            commondomain["both"] = both
            commondomain["domains_number"] = len(domains_list)
            commondomain["urls_number"] = len(urls_list)
            commondomain["both_number"] = len(both)
            commondomains[version] = commondomain

        for i in self.input():
            i.cleanup()

        with self.output().open('w') as f:
            json.dump(commondomains, f, sort_keys=True)


class PkgUrl(luigi.Task):
    apks = luigi.TupleParameter()
    pkg = luigi.Parameter()
    libs_folder = cfg.libradar_app_libs_folder
    apk_info_folder = cfg.info_app_folder

    # requires json of single releases
    def requires(self):
        info_path = os.path.join(cfg.info_app_folder,
                                 self.pkg, self.pkg + ".json")
        libs_path = os.path.join(cfg.libradar_app_libs_folder,
                                 self.pkg, self.pkg + ".json")
        return {'stringoid_parse': [StringoidParse(file_name=apk) for
                                    apk in self.apks],
                'info_path': ExternalFile(file_name=info_path),
                'libs_path': ExternalFile(file_name=libs_path)
                }

    # output is the json file with aggregated info of the app
    def output(self):
        output_file = os.path.join(cfg.stringoid_pkgurl_folder,
                                   self.pkg + ".json")
        return ExternalFileTarget(output_file)

    def separate_domains(self, domains):
        new_domains = []
        for d, l in domains:
            if '|' in d:
                split_domains = d.split('|')
                for sd in split_domains:
                    new_domains.append((sd, l))
            else:
                new_domains.append((d, l))

        return new_domains

    def run(self):
        pkg_url = defaultdict(dict)
        filtered_pkg_url = defaultdict(dict)
        all_urls = set()
        domain_parser = domain_utils.DomainParser()
        libs_fd = self.input()['libs_path'].open()
        info_fd = self.input()['info_path'].open()

        lp = lib_utils.LibProvider(libs_fd,
                                   lib_names=True,
                                   unknown_libs=True,
                                   apk_info_fd=info_fd,
                                   no_libs=False,
                                   unknown_lib_loc=False)
        for i in self.input()['stringoid_parse']:
            with i.open() as url_file:
                urls = json.load(url_file)
                version = i.path.split("_")[-2]
                date = i.path.split("_")[-1].replace(".json", "")
                url_lines = [(url, lp.get_lib(loc, version, self.pkg))
                             for url, loc in urls.items()]
                url_lines = self.separate_domains(url_lines)
                all_urls.update(set(url_lines))
                pkg_url[version]['url'] = url_lines
                pkg_url[version]['date'] = date
                if 'stringoid_error' in urls.keys():
                    pkg_url[version]['error'] = urls['stringoid_error']
        url_mapping = domain_parser.cluster_domains(list(all_urls))
        for version, value in pkg_url.items():  # TODO: refactor
            url_list = value['url']
            mapped_url_lines = [url_mapping[key] for key in url_list]
            mapped_url_lines = list(filter(None, mapped_url_lines))
            filtered_pkg_url[version]['url'] = mapped_url_lines
            filtered_pkg_url[version]['date'] = pkg_url[version]['date']
            if 'error' in value.keys():
                filtered_pkg_url[version]['error'] = value['error']

        for i in self.input()['stringoid_parse']:
            i.cleanup()

        with self.output().open('w') as f:
            json.dump(filtered_pkg_url, f, sort_keys=True)


class StringoidDomainsMatrix(luigi.Task):
    apks = luigi.TupleParameter()
    pkg = luigi.Parameter()

    # requires application json
    def requires(self):
        return {'json': CommonDomains(pkg=self.pkg, apks=self.apks)}

    # output is the heatmap
    def output(self):
        output_file = os.path.join(cfg.stringoid_domains_matrix_folder,
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
            ylabels.append("No URL found")

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
            commondomains = json.load(data_file)
            for apkversion, value in commondomains.items():

                both = value["both"]
                domains = value["domains"]
                urls = value["urls"]
                apk = {}
                apk['vercode'] = apkversion
                apk_data = {}
                for url in both:
                    # simple case
                    apk_data[url] = 30
                for url in domains:
                    apk_data[url] = 20
                for url in urls:
                    apk_data[url] = 10

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


class StringoidDomainsHeatmap(luigi.Task):
    apks = luigi.TupleParameter()
    pkg = luigi.Parameter()

    # requires application json
    def requires(self):
        return {'json': CommonDomains(pkg=self.pkg, apks=self.apks)}

    # output is the heatmap
    def output(self):
        output_file = os.path.join(cfg.stringoid_domains_matrix_folder,
                                   self.pkg + "_StringoidDomains.pdf")
        return ExternalFileTarget(output_file)

    # creates the heatmap of permission use and saves it to a file
    def create_heatmap(self, data, row_labels, col_labels):

        # colors library labels with red
        row_colors = []
        for label in row_labels:
            if ":" in label:
                c = "red"
            else:
                c = "white"
            row_colors.append(c)

        pdata = pd.DataFrame(data, index=row_labels,
                             columns=col_labels)
        pdata.index.name = "url"
        pdata.columns.name = "Versions"

        # TODO put this in all heatmap creation. refactor code
        row_cluster = True if data.shape[0] > 1 else False

        vmax = pdata.values.max()
        splot = heatmaps.plot_heatmap(pdata, vmax=vmax, row_colors=row_colors,
                                      row_cluster=row_cluster)

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


class StringoidMatrix(luigi.Task):
    apks = luigi.TupleParameter()
    pkg = luigi.Parameter()

    # requires application json
    def requires(self):
        return {'json': PkgUrl(pkg=self.pkg, apks=self.apks)}

    # output is the heatmap
    def output(self):
        output_file = os.path.join(cfg.stringoid_matrix_folder,
                                   self.pkg,
                                   self.pkg + ".json")
        return ExternalFileTarget(output_file)

    def get_matrix(self, app):
        """ returns a matrix with source-sink pairs on the y-axis
        and version on the x-axis """
        # get all source-sink combinations as y-labels
        ylabels = []
        for apk in app['apks']:
            for data in apk['data'].keys():
                if data not in ylabels:
                    ylabels.append(data)
        ylabels.sort()

        if len(ylabels) == 0:
            ylabels.append("No URL found")

        matrix = numpy.zeros(shape=(len(app['apks']), len(ylabels)))
        xlabels = []

        for i in range(0, len(app['apks'])):
            apk = app['apks'][i]
            label = apk['vercode'] + "~" + apk['date']
            xlabels.append(label)
            values = []
            for el in ylabels:
                if el in apk['data'].keys():
                    val = apk['data'][el]  # don't limit values here
                    values.append(val)
                else:
                    if 'error' in apk.keys():
                        values.append(-1)
                    else:
                        values.append(0)
            matrix[i] = values

        return matrix.T, ylabels, xlabels

    def run(self):
        # create app dictionary

        app = {'pkg': self.pkg, 'apks': []}
        with open(self.input()['json'].path) as data_file:
            pkg_url = json.load(data_file)
            for apkversion, value in pkg_url.items():
                data = value['url']
                date = value['date']
                apk = {}
                apk['vercode'] = apkversion
                apk_data = {}
                for url in data:
                    # simple case
                    apk_data[url] = 1 if ":" in url else 2

                apk['data'] = apk_data
                apk['date'] = date
                if 'error' in value.keys():
                    apk['error'] = value['error']
                app['apks'].append(apk)
        app['apks'] = sorted(app['apks'], key=lambda k: int(k['vercode']))

        matrix, ylabels, xlabels = self.get_matrix(app)
        data = {'m': matrix.tolist(),
                'yl': ylabels,
                'xl': xlabels}

        # write matrix to json file
        with self.output().open('w') as data_file:
            json.dump(data, data_file)


class StringoidHeatmap(luigi.Task):
    apks = luigi.TupleParameter()
    pkg = luigi.Parameter()

    # requires application json
    def requires(self):
        return {'matrix': StringoidMatrix(pkg=self.pkg, apks=self.apks)}

    # output is the heatmap
    def output(self):
        output_file = os.path.join(cfg.stringoid_heatmap_folder,
                                   self.pkg + ".pdf")
        return ExternalFileTarget(output_file)

    # creates the heatmap of permission use and saves it to a file
    def create_heatmap(self, data, row_labels, col_labels):

        pdata = pd.DataFrame(data, index=row_labels, columns=col_labels)
        pdata.index.name = "url"
        pdata.columns.name = "Versions"

        # turn off row clustering if there is only one row
        row_cluster = True if data.shape[0] > 1 else False

        # colors library labels with red
        row_colors = []
        for label in row_labels:
            if ":" in label:
                c = "red"
            else:
                c = "white"
            row_colors.append(c)

        vmax = pdata.values.max()
        splot = heatmaps.plot_heatmap(pdata, vmax=vmax, row_colors=row_colors,
                                      row_cluster=row_cluster)

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


class ApkUrlAnalysis(luigi.WrapperTask):
    """ WrapperTask to analyze with FlowDroid all apks in the apks folder """
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
            yield StringoidHeatmap(pkg=pkg, apks=apks)


if __name__ == '__main__':
    luigi.run(main_task_cls=ApkUrlAnalysis)
