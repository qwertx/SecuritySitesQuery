import re
import os
import logging
import urllib.request
import urllib.error
from datetime import datetime
from query_app.config import UPDATE_INTERVAL, DATA_PATH

LISTS = ['domain_recommended',
         'ip_recommended',
         'domain_standard',
         'ip_standard',
         'compromised_url']
URLS = ['https://zeustracker.abuse.ch/blocklist.php?download=baddomains',
        'https://zeustracker.abuse.ch/blocklist.php?download=badips',
        'https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist',
        'https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist',
        'https://zeustracker.abuse.ch/blocklist.php?download=compromised']
PATHS = [DATA_PATH + '/zeus_domain_recommended',
         DATA_PATH + '/zeus_ip_recommended',
         DATA_PATH + '/zeus_domain_standard',
         DATA_PATH + '/zeus_ip_standard',
         DATA_PATH + '/zeus_url_compromised']
QUERY = [[0, 2, 4], [1, 3, 4]]  # 关键词的搜索顺序

logger = logging.getLogger('main')


class Zeus(object):
    """
    从https://zeustracker.abuse.ch/blocklist.php下载列表，
    搜索下载的文件并返回结果
    """
    def __init__(self, keyword, kw_type=0):
        self.re = '.*' + keyword + '.*'
        self.kwType = kw_type             # 0为域名, 1为IP
        self.query = QUERY[self.kwType]
        self.results = {}

    @staticmethod
    def download_list(i):
        try:
            logger.info('downloading list %s from zeustracker', LISTS[i])
            urllib.request.urlretrieve(URLS[i], PATHS[i])
        except Exception:
            logger.error('download from zeus failed', exc_info=True)
            print('从zeustracker下载列表%s失败, 使用本地数据' % LISTS[i])

    def if_download(self):
        now = datetime.now().timestamp()
        # 文件不存在或超过UPDATE_INTERVAL就重新下载
        for i in self.query:
            # 距离文件上次更新的时间
            if not os.path.exists(PATHS[i]) or \
                    now - os.stat(PATHS[i]).st_mtime > UPDATE_INTERVAL:
                self.download_list(i)

    def remove_repeats(self):
        s1 = set(self.results[self.query[0]])
        s2 = set(self.results[self.query[1]])
        s2 = s2 - s1
        self.results[self.query[1]] = list(s2)

    def search(self):
        # self.if_download()
        # 搜索匹配的行
        for i in self.query:
            self.results[i] = []
            try:
                logger.info('search from zeus list %s', LISTS[i])
                with open(PATHS[i], 'r') as f:
                    for line in f.readlines():
                        if not re.match(r'^#', line) and re.match(self.re, line):
                            self.results[i].append(line.strip())
            except Exception:
                logger.error('search failed', exc_info=True)
                print('搜索zeustracker列表%s失败, 请重试以下载相应的文件' % LISTS[i])
        self.remove_repeats()
        return self.results
