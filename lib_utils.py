# util function to process libraries
import json
import logging
import os
import tempfile

logger = logging.getLogger('luigi-interface')  # TODO: check this


class LibProvider():
    libs_dict = {}

    #    def __init__(self, libs_path, lib_names=False, unknown_libs=False, apk_info_path=""):
    def __init__(self, libs_fd, lib_names, unknown_libs, apk_info_fd, unknown_lib_loc, no_libs=False):
        self.lib_names = lib_names
        self.unknown_libs = unknown_libs
        self.unknown_lib_loc = unknown_lib_loc
        self.no_libs = no_libs
        lib_content = self._get_lib_dict(libs_fd)
        if len(lib_content) != 0:
            for version, values in lib_content.items():
                val = {v + '.': k for k, v in values.items()}  # for a particular version locations are defined strictly
                self.libs_dict[version] = val
        else:
            logger.warning("Error: No lib location information provided!")
        self.app_info = self._get_app_info(apk_info_fd)

    def get_lib(self, loc, version, pkg="#"):
        if self.no_libs:
            return ""
        formatted_loc = loc + '.' if not loc.endswith('.') else loc
        if version in self.libs_dict.keys():
            for lib_loc in self.libs_dict[version].keys():
                if formatted_loc.startswith(lib_loc):
                    return self.libs_dict[version][lib_loc] if self.lib_names else "LIB"
        return ""

    @staticmethod
    def _get_lib_dict(libs_fd):
        try:
            lib_content = json.load(libs_fd)['libs']
            libs_fd.close()
            return lib_content
        except IOError:
            logger.warning("Error: failed to read lib data!")
            return dict()

    @staticmethod
    def _get_app_info(apk_info_fd):
        try:
            info_content = json.load(apk_info_fd)
            apk_info_fd.close()
            return info_content
        except IOError:
            logger.warning("Error: failed to read info data!")
            return dict()

    def infer_pkg(self, pkg, version):
        pkg = self.get_reduced_pkg(pkg)
        info = self.app_info.get(version, "")
        activity = info.get("activity", "")
        if activity is "":
            return pkg
        res = os.path.commonprefix([pkg, activity.lower()])
        return res.strip('.')

    '''Reduce package name to cover cases when developers use their own sdks and libs, i.e. com.kakao.sdk in com.kakao.messenger
    '''

    @staticmethod
    def get_reduced_pkg(pkg):
        pkg = pkg.replace('/', ".")
        pkg_split = pkg.split('.')
        pkg_prefix = '.'.join(pkg_split[:-1])
        return pkg_prefix + "." if len(pkg_split) > 2 and len(pkg_prefix) > 8 else pkg + "."

    @staticmethod
    def get_fully_reduced_pkg(pkg):
        """ Reduce package name to the shortest possible, having at lest
        two strings split by a period (.) and a minimum length of 8,
        i.e. com.kakao.sdk.package to com.kakao
        """
        pkg_split = pkg.replace('/', ".").split('.')
        reduced_pkg = '.'.join(pkg_split)
        i = 1
        # cycle until end condition is met (min length 8 or
        # split of length two)
        while True:
            new_reduced = '.'.join(pkg_split[:-i])
            if len(pkg_split) - i < 2 or len(new_reduced) < 8:
                return reduced_pkg + '.'
            reduced_pkg = new_reduced
            i += 1


if __name__ == "__main__":
    # data = [("9.google.com", 'com/google/q'), ("i.google.com", "wewe/q"), ("google.com", 'com/google/q'), ("facebook.com", "com/face/"), ("https://graph.%s", "'com/face/")]
    f = tempfile.NamedTemporaryFile('w', delete=False)
    i = tempfile.NamedTemporaryFile('w', delete=False)
    libs = {'libs': {'1': {"Google": "com/google", "Facebook": "com/face"}}}
    info_mock = {"1": {"activity": "es.imd.two", "platformBuildVersionName": "5.0.1-1624448", "sdkVersion": "12",
                       "targetSdkVersion": "21", "versionName": "100"}}
    f.write(json.dumps(libs))
    i.write(json.dumps(info_mock))
    f.close()
    i.close()
    # noinspection PyArgumentList
    lp = LibProvider(f.name, lib_names=True, unknown_libs=True, apk_info_fd=i.name)
    print(lp.get_lib("com/google/support", "1", "es.imd.one"))
    print(lp.get_lib("es/imd/a/b", "1", "es.imd.one"))
    print(lp.get_lib("com/unknown/a/b", "1", "es.imd.one"))
    print(lp.get_lib("es/imd/one/a/b", "1", "es.imd.one"))
    os.remove(f.name)
    os.remove(i.name)
    print(LibProvider.get_reduced_pkg("com.kakao.home"))
    print(LibProvider.get_reduced_pkg("co.cm.kakao"))
