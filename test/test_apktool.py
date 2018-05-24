import unittest
import sys
import luigi
import os
sys.path.append("..")
import luigi_apktool as apktool


class TestApktoolMethods(unittest.TestCase):
    maxDiff = None  # for assertEqual

    def test_manifest_diff(self):
        file_old = "resources/AndroidManifest_7.xml"
        file_new = "resources/AndroidManifest_8.xml"
        test_class = apktool.OutFileDiff(pkg="", apks="", output_folder="")
        res = test_class.get_manifest_diff(file_old, file_new)
        expected_res = {"receiver": {
                        "add": 0, "changed": 0, "remove": 0},
                        "activity": {"add": 1, "changed": 1, "remove": 0},
                        "provider": {"add": 0, "changed": 0, "remove": 0},
                        "service": {"add": 0, "changed": 1, "remove": 0},
                        "permission": {"add": 0, "changed": 1, "remove": 0}}

        self.assertEqual(res, expected_res)
        print "manifest_diff passed"

    def test_diff_heatmap(self):
        apktool.ApktoolHeatmap.requires = lambda _: {}
        apktool.ApktoolHeatmap.input = lambda _: {'json': luigi.LocalTarget(path=os.path.join('resources/com.apusapps.launcher.json'))}
        test_class = apktool.ApktoolHeatmap(pkg="com.apusapps.launcher", apks="", output_folder="resources")
        test_class.run()
        print "diff_heatmap passed >> check heatmap png in 'resources/com.apusapps.launcher' folder"

    def test_detailed_comparison(self):
        test_class = apktool.OutFileDiff(pkg="", apks="", output_folder="")
        apps = ["resources/com.apusapps.launcher_7_2014-07-22.json", "resources/com.apusapps.launcher_8_2014-07-25.json"]
        out_diff = test_class.do_detailedcomparison(apps, 0)
        print "#FIXME: Right now 'previous number of files' field in not checked since we use real folder structure to compute it, refactor to use json file."
        expected_res = {'unknown': {'add': 0, 'previous number of files': 0, 'change': 0, 'remove': 0},
                        'AndroidManifest.xml': {
                            'receiver': {'add': 0, 'changed': 0, 'remove': 0},
                            'activity': {'add': 1, 'changed': 1, 'remove': 0},
                            'provider': {'add': 0, 'changed': 0, 'remove': 0},
                            'service': {'add': 0, 'changed': 1, 'remove': 0},
                            'permission': {'add': 0, 'changed': 1, 'remove': 0}
                        },
                        'smali': {'add': 34, 'previous number of files': 0, 'change': 243, 'remove': 14},
                        'res': {
                            'values': {'add': 1, 'changed folder': {'add': [], 'remove': []},
                                       'previous number of files': 0, 'change': 13, 'remove': 0},
                        'drawable': {'add': 15, 'changed folder': {'add': [], 'remove': []},
                                     'previous number of files': 0, 'change': 30, 'remove': 7}, 'previous number of files': 0,
                        'layout': {'add': 9, 'changed folder': {'add': [], 'remove': []}, 'previous number of files': 0, 'change': 10, 'remove': 1}}}
        self.assertEqual(out_diff, expected_res)
        print "detailed_comparison passed"


if __name__ == '__main__':

    try:
        unittest.main()
    except:
        # this is a stub to prevent python from closing the current session in the interactive mode
        print "Test finished"
