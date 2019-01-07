#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import gzip
import json
import logging
import os
import re
from collections import OrderedDict
from collections import namedtuple
from datetime import datetime
from statistics import mean
from statistics import median

#
# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log",
    'LOG_FILE': 'logger.log'
}
log_name_pattern = re.compile(r'([a-zA-Z0-9\-]+).\S+(\d{8}).(gz|log|txt)')
log_pattern = r"""(?P<remote_addr>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\s+](?P<remote_user>\w+)?[\s\-](?P<http_x_real_ip>.+?)\[(?P<time_local>\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2} [\+|\-]\d{4})\]\s+\"(?P<method>\S{3,10}) (?P<request>\S+) HTTP\/1\.\d\" (?P<status>\d{3}) (?P<body_bytes_sent>\d+) \"(?P<http_referer>[\-|\S+]+)?\" \"(?P<http_user_agent>.+)\" \"(?P<http_x_forwarded_for>.+)\" \"(?P<http_X_REQUEST_ID>.+)\" \"(?P<http_X_RB_USER>.+)\" (?P<request_time>\d+\.\d+)"""

handlers_list = [logging.StreamHandler()]

logging.basicConfig(format='[%(asctime)s] %(levelname).1s %(message)s',
                    datefmt='%Y.%m.%d %H:%M:%S',
                    handlers=handlers_list,
                    level=logging.INFO)
logger = logging.getLogger('log_analyzer')


def main():
    log_name = 'nginx-access-ui'
    parser = argparse.ArgumentParser(usage='%(prog)s --config configfile.json',
                                     description='Log parser', formatter_class=argparse.MetavarTypeHelpFormatter)
    parser.add_argument('--config', type=str,
                        help='Path to external config file (default: local config will be used)')
    args = parser.parse_args()

    settings = get_settings(args.config)

    if settings.get('LOG_FILE'):
        fh = logging.FileHandler(settings.get('LOG_FILE'))
        logger.addHandler(fh)

    log_dir = settings['LOG_DIR']
    if not os.path.exists(log_dir):
        logger.error('No such directory {}'.format(log_dir))
        exit()

    logfile = get_latest_logfile(log_dir, log_name)
    if not logfile:
        logger.info('No logfile for analyze')
        exit()

    report_path = 'report-{}.{}.{}.html'.format(logfile.date.year, logfile.date.month, logfile.date.day)
    report_path = os.path.join(settings['REPORT_DIR'], report_path)
    if not os.path.exists(settings['REPORT_DIR']):
        os.mkdir(settings['REPORT_DIR'])
    elif os.path.exists(report_path):
        logger.info('Report already exist {}'.format(report_path))
        exit(0)

    logger.info('Start log analyzing...')
    logs_data = parse_log(logfile.path)
    logs = logs_data['logs']
    size_logs = logs_data['size_logs']
    issue_counter = logs_data['issue_counter']
    sum_request_time = logs_data['sum_request_time']

    if round(issue_counter / size_logs * 100) > 1:
        logger.error('Too much wrong logs, which can\'t be analyzed')
        exit()

    result_data_list = []
    for url, time_list in logs.items():
        item = {
            'count': len(time_list),
            'count_perc': round(len(time_list) / size_logs * 100, 3),
            'time_sum': round(sum(time_list), 3),
            'time_perc': round(sum(time_list) / sum_request_time * 100, 3),
            'time_avg': round(mean(time_list), 3),
            'time_max': round(max(time_list), 3),
            'time_med': round(median(time_list), 3),
            'url': url,
        }
        result_data_list.append(item)

    result_data_list = sorted(result_data_list, key=lambda x: x['time_sum'], reverse=True)[:settings['REPORT_SIZE']]
    logger.info('Save report to {}'.format(report_path))
    save_report(result_data_list, report_path)


def get_settings(configfile):
    """ Get settings of external config file if it exist, and then update of local settings
    :param str configfile: Path to external json file with settings
    :return: Dictionary with current settings
    """
    if configfile is None:
        pass
    elif not configfile.endswith('.json'):
        logger.error('Configfile must have json file')
    elif os.path.exists(configfile) and os.path.getsize(configfile):
        with open(configfile) as file:
            config.update(json.loads(file.read()))
    return config


def get_latest_logfile(log_dir, name):
    """ Find latest logfile with required longname
    :param str log_dir: Path to logs
    :param str name: Log name
    :return: str|None, path to latest required logfile if it was found, else None
    """
    log_file = namedtuple('Log_file', ['date', 'extension', 'path'])

    logs_list = os.listdir(log_dir)

    found_logfile = None

    for log_item in logs_list:
        if not log_name_pattern.findall(log_item):
            continue
        log_name, date, ext = log_name_pattern.findall(log_item)[0]

        if log_name != name:
            continue

        item_date = datetime.strptime(date, '%Y%m%d')

        if not found_logfile or item_date > found_logfile.date:
            found_logfile = log_file(item_date, ext, os.path.join(log_dir, log_item))

    return found_logfile


def get_logs(file):
    """ Generator of logs with url and request_time
    :param GzipFile|TextIOWrapper file: File with logs
    :return: None|namedtuple(url, request_time)
    """
    Log = namedtuple('Log', ['url', 'request_time'])
    pattern = re.compile(log_pattern)
    for line in file:
        line = line.decode()
        if not pattern.search(line):
            yield None
            continue

        log_line = pattern.search(line)
        request_url = log_line.group('request')
        request_time = log_line.group('request_time')

        yield Log(request_url, float(request_time))


def parse_log(path):
    """ Parse and count of log lines, common time_request and bad lines
    :param str path: Path to logfile
    :return: Dictionary
    """
    filename, extension = os.path.splitext(path)
    file = gzip.open(path) if extension == '.gz' else open(path)

    result_logs = {}
    common_counter = 0
    time_request_counter = 0
    issue_counter = 0
    for log in get_logs(file):
        common_counter += 1
        if log is None:
            issue_counter += 1
            continue
        elif log.url in result_logs:
            time_list = result_logs[log.url]
            time_list.append(log.request_time)
        else:
            time_list = [log.request_time]
        result_logs[log.url] = time_list
        time_request_counter += log.request_time
    file.close()

    result_logs = OrderedDict(sorted(result_logs.items(), key=lambda x: len(x[1]), reverse=True))

    result = {
        'logs': result_logs,
        'size_logs': common_counter,
        'issue_counter': issue_counter,
        'sum_request_time': time_request_counter,
    }
    return result


def save_report(data, report_path):
    """ Save data to report file
    :param list data: json data of requests
    :param str report_path: path to report file
    """
    template_report = 'report.html'

    with open(template_report) as f:
        lines = f.readlines()

    for index in range(len(lines)):
        if re.search(r'\$table_json', lines[index]):
            lines[index] = re.sub(r'\$table_json', str(data), lines[index])
            break

    with open(report_path, 'w') as f:
        f.writelines(lines)


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        logger.exception(err)
