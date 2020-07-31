#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
查询主程序
"""

import re
import os
import sys
import ssl
import click
import pickle
import datetime
import logging.config
from query_app.client.query_client import QueryClient
from query_app.config import CONFIG, LOGGING, DATA_PATH


APP_DESC = """
    一个搜索安全相关网站的命令行小程序, 可以搜索IP/域名/证书.
    Type 'ssq --help' to get help. Last update: 2018-09-15
"""


logging.config.dictConfig(LOGGING)
logger = logging.getLogger('main')

OUTPUT_PATH_FILE = DATA_PATH + '/output_path'
ssl._create_default_https_context = ssl._create_unverified_context


def check_output_path():
    path = ''
    if os.path.exists(OUTPUT_PATH_FILE):
        try:
            logger.info('try to get output path')
            with open(OUTPUT_PATH_FILE, 'rb') as f:
                path = pickle.load(f)
        except Exception:
            logger.error('read from output_path_file failed', exc_info=True)
    else:
        while True:
            path = input('输出路径不存在,请指定路径\n')
            if os.path.exists(path):
                logger.info('new output path: %s', path)
                f = open(OUTPUT_PATH_FILE, 'wb')
                pickle.dump(path, f)
                break
    return path


def check_version():
    logger.info('check environment')
    if float(sys.version[:3]) < 3.5:
        raise RuntimeError('at least Python 3.5 is required!')
    logger.info('start setting params')


@click.command()
@click.argument('keyword', required=True)
@click.argument('site', type=int, nargs=-1)
@click.option('-m', '--mode', default=0,
              help='''手动指定关键词类型, 0:自动识别(默认), 1:IP, 2:域名/证书名, 3:证书SHA1
                   注意:如果手动指定了类别就不会进行识别!''')
@click.option('-u', '--update', default=1,
              help='是否在搜索前更新本地数据, 0:不更新, 1:更新(每天仅更新一次,默认)')
@click.option('-o', '--output', default=0,
              help='指定输出类型, 0:输出json和xlsx(默认), 1:仅输出json, 2:仅输出xlsx, 3:仅输出到控制台,不写入文件')
@click.option('-n', '--name', default='',
              help='指定输出文件名,默认名为查询时间')
# @click.option('-p', '--path', default=OUTPUT_PATH,
#               help='指定输出路径,默认为~/ssq_output')
def parse_command(keyword, mode, site, update, output, name):
    """
    支持4种查询参数,\n
    关键词后面可以紧接着用数字指定搜索的站点, 不指定则查询所有网站:\n
    1:Shodan, 2:MDL, 3:SSLBL, 4:ZeusTracker, 5:VirusTotal 可以指定多个\n
    (测试环境: ubuntu 18.04)
    """
    check_version()
    CONFIG['path'] = check_output_path()
    if not os.path.exists(CONFIG['path']):
        print('输出路径不存在')
        return

    CONFIG['keyword'] = keyword
    # 判断关键词类型
    if 0 < mode < 4:
        CONFIG['mode'] = mode
    else:
        CONFIG['mode'] = kw_type(keyword)

    if CONFIG['mode'] == -1:
        print('IP地址错误,请重试')
        return

    if site and set(site) < {1, 2, 3, 4, 5}:
        CONFIG['site'] = site
    else:
        CONFIG['site'] = (1, 2, 3, 4, 5)
    # print(site)
    CONFIG['update'] = 0 if update == 0 else 1
    CONFIG['output'] = output if 0 < output < 4 else 0

    # # 替换路径中的'~'
    # if path and path[0] == '~':
    #     path = expanduser('~') + path[1:]
    # # 路径是否存在
    # if path == OUTPUT_PATH:
    #     CONFIG['path'] = OUTPUT_PATH
    # elif os.path.exists(path):
    #     CONFIG['path'] = path
    # else:
    #     print('指定路径不存在,将使用默认路径')
    #     CONFIG['path'] = OUTPUT_PATH

    # 文件名是否重复
    now = str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    if name and os.path.exists(CONFIG['path'] + '/' + name):
        print('文件已经存在,将使用默认文件名')
        CONFIG['name'] = now
    elif name:
        CONFIG['name'] = name
    else:
        CONFIG['name'] = now

    logger.info('开始查询,参数为: %s', CONFIG)
    start_query_client()


def kw_type(kw):
    """
    判断查询词类型(未指定类型时)
    """
    # ip
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', kw):
        parts = kw.split('.')
        for p in parts:
            if -1 < int(p) < 256:
                continue
            else:
                return -1
        return 1
    # sha1
    elif re.match(r'^[0-9a-z]{40}$', kw):
        return 3
    # 其他
    else:
        return 2


def start_query_client():
    qc = QueryClient()
    qc.start()


def main():
    print(APP_DESC)
    parse_command()


if __name__ == '__main__':
    main()
