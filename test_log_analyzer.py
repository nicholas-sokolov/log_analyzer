import json
import os
import shutil
import stat
import time
import unittest

from log_analyzer import config


class SimplisticTest(unittest.TestCase):

    @staticmethod
    def update_configfile(filename, settings):
        """ Update JSON configfile and save it
        :param str filename:
        :param dict settings:
        """
        config.update(settings)
        with open(filename, 'w') as f:
            json.dump(config, f)

    @staticmethod
    def remove(*args):
        for item in args:
            os.chmod(item, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
            if os.path.isdir(item):
                shutil.rmtree(item)
            else:
                os.remove(item)

    def testBasic(self):
        dir_reports = './test_report_dir'
        settings = {
            'REPORT_DIR': dir_reports,
            'REPORT_SIZE': 10,
        }
        configfile = 'test_config.json'
        self.update_configfile(configfile, settings)
        os.system('log_analyzer.py --config {}'.format(configfile))
        self.assertTrue(os.path.exists(dir_reports), 'No report directory')
        self.remove(dir_reports, configfile)

    def testDoubleBasic(self):
        os.system('log_analyzer.py')
        dir_reports = './test_report_dir'
        settings = {
            'REPORT_DIR': dir_reports,
            'REPORT_SIZE': 10,
        }
        configfile = 'test_config.json'
        self.update_configfile(configfile, settings)
        os.system('log_analyzer.py --config {}'.format(configfile))
        self.assertTrue(os.path.exists(dir_reports), 'No report directory')
        start = time.time()
        os.system('log_analyzer.py --config {}'.format(configfile))
        self.assertTrue(time.time() - start < 10, "Second run more then 10 sec.")
        self.remove(dir_reports, configfile)


if __name__ == '__main__':
    unittest.main()
