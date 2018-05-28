import os
import random
import tempfile

import luigi
import luigi.format
from luigi import LocalTarget
from luigi.contrib.ssh import RemoteTarget

from commons import commons
import cfg


class LocalFile(luigi.ExternalTask):
    file_name = luigi.Parameter()

    def output(self):
        return luigi.LocalTarget(self.file_name)


class ExternalFile(luigi.ExternalTask):
    file_name = luigi.Parameter()

    def output(self):
        return ExternalFileTarget(self.file_name, file_type='regular')


class ApkFile(luigi.ExternalTask):
    file_name = luigi.Parameter()

    def output(self):
        pkg, _, _ = commons().get_apk_data(self.file_name)
        if not self.file_name.endswith('.apk'):
            self.file_name += '.apk'
        relative_file_path = os.path.join(pkg, self.file_name)
        return ExternalFileTarget(relative_file_path, root_dir=cfg.apks_folder, file_type='apk')


class ExternalFileTarget(luigi.target.FileSystemTarget):
    # @property
    # def path(self):

    def __init__(self, path, file_type='regular', root_dir=None, format=None, **kwargs):
        self.is_remote = commons().is_remote
        if root_dir:
            full_path = os.path.join(root_dir, path)
        else:
            if self.is_remote:
                full_path = os.path.join(commons().remote_root, path)
            else:
                full_path = os.path.join(commons().local_root, path)

        self.file_type = file_type
        self.format = format
        if self.is_remote:
            host = commons().SSH_HOST
            port = commons().SSH_PORT
            kwargs['port'] = port
            self._target = RemoteTarget(full_path, host, format=format, **kwargs)
            if file_type == 'apk':  # create temporary local copy
                self.local_path = os.path.join(tempfile.gettempdir(), 'luigi-{}-{}.apk'.format(os.path.basename(path),
                                                                                               random.randint(0,
                                                                                                              999999999)))
                self._target.get(self.local_path)
        else:
            self._target = LocalTarget(full_path, format=format, **kwargs)

        if self.is_remote and self.file_type == 'apk':
            path = self.local_path
        else:
            path = self._target.path
        super(ExternalFileTarget, self).__init__(path)  # XXX: check if this is right

    def fs(self):
        return self._target.fs

    def open(self, mode='r'):
        return self._target.open(mode)

    def exists(self):
        return self._target.exists()

    def remove(self):
        return self._target.remove()

    def cleanup(self):
        try:
            os.remove(self.local_path)
        except (OSError, AttributeError):
            pass
