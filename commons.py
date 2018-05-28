import luigi
import os
import sys
import re

sys.path.append("..")
import cfg
import csv


class commons(luigi.Config):
    is_remote = luigi.BoolParameter(default=False)
    SSH_HOST = luigi.Parameter(default='134.96.225.222')
    SSH_PORT = luigi.Parameter(default='2222')
    # remote_path = luigi.Parameter(default='/home/kuznetsov/imd/static_analysis/data')
    remote_root = luigi.Parameter()
    local_root = cfg.evo_data_folder
    permission_mapping = luigi.Parameter()  # TODO refactor
    hostname = luigi.Parameter()

    @staticmethod
    def get_apk_data(file_path):
        basename = commons().strip_file_name(file_path)
        pattern = re.compile(r"(?P<pkg>.+)_(?P<ver>[0-9]+)(_(?P<date>[0-9\-]+))?$")  # date can be empty
        match = pattern.match(basename)
        if match is None:
            raise ValueError("Problem with file name: {fn}".format(fn=file_path))
        pkg = match.group("pkg")
        vercode = match.group("ver")
        date = match.group("date")
        return pkg, vercode, date

    @staticmethod
    def get_apk_name(pkg, vercode, date):
        return "{pkg}_{vercode}_{date}".format(pkg=pkg, vercode=vercode, date=date)

    @staticmethod
    def strip_file_name(file_path):
        bn = os.path.basename(file_path)
        return re.sub('\.(xml|json|apk|txt)$', '', bn)

    @staticmethod
    def csv_file_to_dict(filename):
        with open(filename, 'r') as infile:
            reader = csv.reader(infile, delimiter=';')
            dictionary = {rows[0]: rows[1] for rows in reader}
            return dictionary
