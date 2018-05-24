# coding=utf-8
import json
import logging

import luigi
import matplotlib

matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy
import os
import subprocess
import sys
import re

sys.path.append("..")
import cfg
import domain_utils
import pandas as pd
import seaborn as sns

from collections import defaultdict

logger = logging.getLogger('luigi-interface')


# python luigi_dynamic_analysis.py AllAppAnalysis --local-scheduler
# autopep8 luigi_dynamic_analysis.py --in-place
# export PATH=/usr/local/bro/bin:$PATH


class ExternalFile(luigi.ExternalTask):
    """ Represents an external file for the Luigi pipeline. """
    ext_file = luigi.Parameter()

    def output(self):
        return luigi.LocalTarget(self.ext_file)


class DomainDiff(luigi.Task):
    apks = luigi.Parameter()
    pkg = luigi.Parameter()
    output_folder = cfg.dynamic_domain_diff_folder

    # requires json of single releases
    def requires(self):
        for apk in self.apks:
            yield BroAppAnalysis(pkg=apk[0], vercode=apk[1], date=apk[2])

    # output is the json file with aggregated info of the app
    def output(self):
        output_file = os.path.join(self.output_folder,
                                   self.pkg,
                                   self.pkg + ".json")
        return luigi.LocalTarget(output_file)

    def do_comparison(self, apps, i):
        domains1 = []
        domains2 = []
        remove = []
        add = []
        diff = {}

        with open(apps[i]) as f_domain1:
            with open(apps[i + 1]) as f_domain2:
                for line in f_domain1:
                    domains1.append(line.strip())
                for line in f_domain2:
                    domains2.append(line.strip())

                for domain in domains1:
                    if domain not in domains2:
                        remove.append(domain)
                for domain in domains2:
                    if domain not in domains1:
                        add.append(domain)

                diff["add"] = add
                diff["remove"] = remove
        return diff

    # creates the json application file
    def run(self):
        out_domains = []
        pkg_diff = {}

        for i in self.input():
            out_domains.append(i.fn)
        out_domains.sort()

        for i in range(len(out_domains) - 1):
            file_diff = self.do_comparison(out_domains, i)
            pkg_diff[out_domains[i + 1].split("_")[-2]] = file_diff

        with self.output().open('w') as f:
            json.dump(pkg_diff, f, sort_keys=True)


class BroAppAnalysis(luigi.Task):
    pkg = luigi.Parameter()
    vercode = luigi.Parameter()
    date = luigi.Parameter()

    dyn_result_folder = cfg.dynamic_analysis_result_folder
    output_folder = cfg.dynamic_bro_analysis_folder

    def get_apk_folder(self):
        foldername = self.pkg + "_" + self.vercode + "_" + self.date + ".apk"
        return os.path.join(self.dyn_result_folder, self.pkg, foldername)

    def requires(self):
        pass
        # return APKFile(apk_folder=self.get_apk_folder())

    def output(self):
        output_file = os.path.join(self.output_folder,
                                   self.pkg,
                                   self.pkg + "_" +
                                   self.vercode + "_" +
                                   self.date, "domains.txt")

        return luigi.LocalTarget(output_file)

    def read_domains_from_file(self, file_name, domains):
        parsing_dns = False
        # cycling all lines, when #types is encountere then start reading
        # domains
        with open(file_name) as f:
            for line in f:
                # if line starts with #types, the following lines will contain
                # domains
                if line.startswith('#types'):
                    parsing_dns = True
                    continue
                if parsing_dns:
                    if line.startswith('#close'):
                        break
                    # getting domain from the line and adding it to array
                    domain = line.split('\t')[9]
                    domains.add(domain)
        return domains

    def run(self):
        # saving current working dir
        initial_working_dir = os.getcwd()

        # changing working dir to a output directory
        dns_dir = os.path.join(
            self.output_folder,
            self.pkg, self.pkg + "_" + self.vercode + "_" + self.date)
        if not os.path.exists(dns_dir):
            os.makedirs(dns_dir)
        os.chdir(dns_dir)

        files_to_analyze = []
        # add all files in the directory which start with 'tcpdump'and end with
        # ".pcap"
        if os.path.exists(self.get_apk_folder()):
            for f in os.listdir(self.get_apk_folder()):
                if os.path.isfile(os.path.join(self.get_apk_folder(), f)) and \
                        f.startswith('tcpdump') and f.endswith(".pcap"):
                    files_to_analyze.append(os.path.join(self.get_apk_folder(),
                                                         f))

        domains = set()
        for i in range(len(files_to_analyze)):
            # if the pcap file has size 0 skip to the next file
            if os.path.getsize(files_to_analyze[i]) == 0:
                continue

            cmd = "bro -r '" + files_to_analyze[i] + "'"
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            logger.debug('Running apktool command: ' + cmd)
            output, err = process.communicate()
            logger.debug('Apktool error: ' + err)
            logger.debug('Apktool out: ' + output)

            dns_file = os.path.join(dns_dir, 'dns.log')
            # if BRO did not generate the dns.log file skipping to next file
            if not os.path.exists(dns_file):
                continue

            # rename "dns.log"
            os.rename("dns.log", "dns" + str(i + 1) + ".log")
            dns_file = os.path.join(dns_dir, "dns" + str(i + 1) + ".log")

            for domain in self.read_domains_from_file(dns_file, domains):
                domains.add(domain)

            # just keep dns files and remove others
            for root, dirs, files in os.walk(dns_dir):
                for name in files:
                    if not name.startswith("dns"):
                        os.remove(os.path.join(root, name))

        with self.output().open('w') as f:
            f.write("\r\n".join(sorted(domains)))

        # going back to the initial working directory
        os.chdir(initial_working_dir)


class AppDnsMatrix(luigi.Task):
    apks = luigi.TupleParameter()
    pkg = luigi.Parameter()
    output_folder = cfg.dynamic_matrix_folder

    # requires application json
    def requires(self):
        for apk in self.apks:
            yield BroAppAnalysis(pkg=apk[0], vercode=apk[1], date=apk[2])

    # output is the heatmap
    def output(self):
        output_file = os.path.join(self.output_folder,
                                   self.pkg,
                                   self.pkg + ".json")
        return luigi.LocalTarget(output_file)

    # returns a matrix with source-sink pairs on the y-axis
    # and version on the x-axis
    def get_matrix(self, app):
        # get all source-sink combinations as y-labels
        ylabels = []
        for apk in app['apks']:
            for domain in apk['domains']:
                if domain not in ylabels:
                    ylabels.append(domain)
        ylabels.sort()

        if len(ylabels) == 0:
            ylabels.append("No domain found")

        matrix = numpy.zeros(shape=(len(app['apks']), len(ylabels)))

        xlabels = []

        for i in range(0, len(app['apks'])):
            apk = app['apks'][i]
            xlabels.append(apk['vercode'])
            values = []
            for el in ylabels:
                if el in apk['domains']:
                    values.append(1)
                else:
                    values.append(0)
            matrix[i] = values

        return matrix.T, ylabels, xlabels

    # creates the heatmap
    def run(self):
        # create app dictionary
        app = {'pkg': self.pkg, 'apks': []}

        for i in self.input():
            # extract vercode from filename
            version = i.fn.split(self.pkg + '_')[-1].split('_')[0]
            with open(i.fn) as data_file:
                lines = [l.strip() for l in data_file]
                dd = domain_utils.DomainParser()

                mapping = dd.cluster_domains(lines)
                maplines = [mapping[key] for key in mapping.keys()]
                apk = {'vercode': version,
                       'domains': maplines}
                app['apks'].append(apk)
        app['apks'] = sorted(app['apks'], key=lambda k: int(k['vercode']))

        matrix, ylabels, xlabels = self.get_matrix(app)
        data = {'m': matrix.tolist(),
                'yl': ylabels,
                'xl': xlabels}

        # write matrix to json file
        with self.output().open('w') as data_file:
            json.dump(data, data_file)


# Task to create the application json, containing all json of single releases
class AppDnsHeatmap(luigi.Task):
    apks = luigi.TupleParameter()
    pkg = luigi.Parameter()
    output_folder = cfg.dynamic_heatmap_folder
    domain_map = luigi.Parameter()
    app_info_folder = cfg.info_app_folder

    # requires application json
    def requires(self):
        return {'matrix': AppDnsMatrix(pkg=self.pkg, apks=self.apks)}

    # output is the heatmap
    def output(self):
        output_file = os.path.join(self.output_folder,
                                   self.pkg + ".pdf")
        return luigi.LocalTarget(output_file)

    def get_col_colors(self, col_labels, app_info):
        # initializing col_colors, the first column is always white
        col_colors = ['white']

        # for each column name we check if the version name is the same
        # as the one of the previous version, in that case we put a red flag.
        # if the versionName has a major change, we put a green flag
        for i in range(1, len(col_labels)):

            actual_vn = app_info[col_labels[i]]['versionName']
            previous_vn = app_info[col_labels[i - 1]]['versionName']
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
            elif (len(a_split) > 2 and len(p_split) > 2 and
                  a_split[1] != p_split[1]):
                col_colors.append('lightgreen')

            # else use default color (white)
            else:
                col_colors.append('white')

        # return col_colors list just created
        return col_colors

    def get_app_info(self):
        appinfo_file = os.path.join(self.app_info_folder,
                                    self.pkg,
                                    self.pkg + '.json')
        with open(appinfo_file) as data_file:
            return json.load(data_file)

    # creates the heatmap of permission use and saves it to a file
    def create_heatmap(self, data, row_labels, col_labels):

        if not os.path.exists(os.path.dirname(self.output().path)):
            os.makedirs(os.path.dirname(self.output().path))

        dpi = 72.27
        fontsize_x_pt = 8
        fontsize_y_pt = 10
        # comput the matrix height in points and inches
        matrix_height_pt = fontsize_y_pt * data.shape[0]
        matrix_height_in = matrix_height_pt / dpi
        matrix_width_pt = fontsize_x_pt * data.shape[1]
        matrix_width_in = matrix_width_pt / dpi

        # compute the required figure height
        top_margin = 0.04  # in percentage of the figure height
        bottom_margin = 0.04  # in percentage of the figure height
        figure_height = 1.8 * matrix_height_in / (1 - top_margin - bottom_margin)
        figure_width = 2 * matrix_width_in / (1 - top_margin - bottom_margin)
        # build the figure instance with the desired height

        # fig, ax = plt.subplots(
        #     figsize=(6, figure_height),
        #     gridspec_kw=dict(top=1 - top_margin, bottom=bottom_margin))

        pdata = pd.DataFrame(data, index=row_labels, columns=col_labels)
        pdata.index.name = "url"
        pdata.columns.name = "Versions"

        # TODO put this in all heatmap creation. refactor code
        row_cluster = True if data.shape[0] > 1 else False

        app_info = self.get_app_info()
        col_colors = self.get_col_colors(col_labels, app_info)

        splot = sns.clustermap(pdata, col_cluster=False, row_cluster=row_cluster,
                               col_colors=col_colors,
                               figsize=(figure_width, figure_height))
        splot.cax.set_visible(False)
        splot.ax_heatmap.set_xlabel("versions", fontsize=10)
        splot.ax_heatmap.set_ylabel("urls", fontsize=10)

        plt.setp(splot.ax_row_dendrogram, visible=False)
        plt.setp(splot.ax_col_dendrogram, visible=False)
        splot.ax_heatmap.yaxis.set_ticks_position('left')
        splot.ax_heatmap.yaxis.set_label_position('left')
        splot.ax_heatmap.set_yticks(numpy.arange(data.shape[0]) + 0.5)
        plt.setp(splot.ax_heatmap.get_yticklabels(), rotation=0)
        plt.setp(splot.ax_heatmap.get_xticklabels(), rotation=90)
        plt.setp(splot.ax_heatmap.get_yticklabels(), fontsize=8)
        plt.setp(splot.ax_heatmap.get_xticklabels(), fontsize=6)

        splot.savefig(os.path.abspath(self.output().path), format='pdf')

    # creates the heatmap
    def run(self):
        # read app matrix from json
        with open(self.input()['matrix'].path) as data_file:
            data = json.load(data_file)

        # get matrix and create the heatmap
        matrix = numpy.array(data['m'])
        self.create_heatmap(matrix, data['yl'], data['xl'])


class ExtractCoveredActivities(luigi.Task):
    pkg = luigi.Parameter()
    vercode = luigi.Parameter()
    date = luigi.Parameter()

    dyn_result_folder = cfg.dynamic_analysis_result_folder
    output_folder = cfg.dynamic_covered_activities_folder

    def get_apk_folder(self):
        foldername = self.pkg + "_" + self.vercode + "_" + self.date + ".apk"
        return os.path.join(self.dyn_result_folder, self.pkg, foldername)

    def requires(self):
        pass

    #        return APKFile(apk_folder=self.get_apk_folder())

    def output(self):
        output_file = os.path.join(self.output_folder,
                                   self.pkg,
                                   self.pkg + "_" +
                                   self.vercode + "_" +
                                   self.date + ".json")

        return luigi.LocalTarget(output_file)

    def run(self):
        files_to_analyze = []
        # add all files in the directory which start with 'tcpdump'and end with
        # ".pcap"
        if os.path.exists(self.get_apk_folder()):
            for f in os.listdir(self.get_apk_folder()):
                if os.path.isfile(os.path.join(self.get_apk_folder(), f)) and \
                        f.startswith('activities_'):
                    files_to_analyze.append(os.path.join(self.get_apk_folder(),
                                                         f))

        # get the activities covered during dynamic analysis
        # over all the run found in the folder
        if len(files_to_analyze) > 0:

            # old cmd
            cmd = "grep ': START' %s/activities_* | grep cmp= | sed 's/^.*cmp=//' | cut -d'}' -f1 | cut -d' ' -f1 | " \
                  "sort | uniq" % (self.get_apk_folder())

            process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, shell=True)
            output, err = process.communicate()

            # escape ansi characters
            ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]')
            clean_out = ansi_escape.sub('', output)

            # put activities in an array
            activities = clean_out.replace('/.', '.').strip().split('\n')

            # cleaning activity strings: if there is a slash we only
            # keep the part following it            
            for i in range(0, len(activities)):
                index = activities[i].find('/')
                if index is not -1:
                    activities[i] = activities[i][index + 1:]

        else:
            activities = []
        with self.output().open('w') as f:
            json.dump(activities, f)


# creates json containing activity coverage for all releases
class AppActivityCoverage(luigi.Task):
    apks = luigi.TupleParameter()
    pkg = luigi.Parameter()
    output_folder = cfg.dynamic_activity_coverage_folder
    info_app_folder = cfg.info_app_folder

    # require covered activities and manifest activities for each apk
    def requires(self):
        covered_act = []

        for apk in self.apks:
            covered_act.append(ExtractCoveredActivities(pkg=apk[0],
                                                        vercode=apk[1],
                                                        date=apk[2]))
        info_app_file = os.path.join(self.info_app_folder,
                                     self.pkg, self.pkg + '.json')

        return {'covered_act': covered_act,
                'info_app': ExternalFile(ext_file=info_app_file)}

    # output is the json with info of activity coverage for each version
    def output(self):
        output_file = os.path.join(self.output_folder,
                                   self.pkg,
                                   self.pkg + ".json")
        return luigi.LocalTarget(output_file)

    # produces json file with activity coverage % for all releases
    def run(self):
        app = {}

        # load info app
        with open(self.input()['info_app'].path) as data_file:
            info_app = json.load(data_file)

        for i in self.input()['covered_act']:

            # extract vercode from filename
            version = i.fn.split(self.pkg + '_')[-1].split('_')[0]

            # extract covered activities from input json
            with open(i.fn) as data_file:
                activities_covered = json.load(data_file)
            act_count = 0

            # if manifest_activities is in info_app we compute coverage
            if 'manifest_activities' in info_app[version].keys():
                manifest_acts = info_app[version]['manifest_activities']

                # count how many activities are in the manifest
                for a in activities_covered:
                    if a in manifest_acts:
                        act_count += 1

                # compute release coverage
                coverage = float(act_count) / len(manifest_acts)
                app[version] = coverage
            # else we set coverage to 0
            else:
                app[version] = 0.0

        # write json file
        with self.output().open('w') as f:
            json.dump(app, f, sort_keys=True)


class AllAppAnalysis(luigi.WrapperTask):
    apks_folder = cfg.fake_apks_folder

    def requires(self):
        apps = defaultdict(set)
        for root, dirs, files in os.walk(self.apks_folder):
            for basename in files:
                if basename.endswith('.apk'):
                    pkg = "_".join(basename.split("_")[:-2])
                    vercode = basename.split("_")[-2]
                    date = basename.split("_")[-1].split('.')[0]
                    apps[pkg].add((pkg, vercode, date))
        for pkg, apks in apps.items():
            #            yield DomainDiff(pkg=pkg, apks=apks)
            yield AppDnsHeatmap(pkg=pkg, apks=apks)
            yield AppActivityCoverage(pkg=pkg, apks=apks)


if __name__ == '__main__':
    luigi.run(main_task_cls=AllAppAnalysis)
