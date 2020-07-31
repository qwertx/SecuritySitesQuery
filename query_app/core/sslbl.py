import os
import pickle
import logging
import shutil
from datetime import datetime
from urllib import request
from html.parser import HTMLParser
from query_app.model.sslbl_db import Certificate, IP, Session
from query_app.config import UPDATE_INTERVAL, DATA_PATH, TEMP_PATH

SSLBL_URL = 'https://sslbl.abuse.ch'
LAST_SHA1_PATH = DATA_PATH + '/last_sha1'
SSLBL_PATH = TEMP_PATH + '/sslbl.html'
LAST_SHA1 = ''  # 上一次存入数据库的位置
logger = logging.getLogger('main')


class ParseDoneException(Exception):
    """
    用于中断解析
    """
    def __init__(self, results):
        self.results = results

    def get_results(self):
        return self.results


class SSLBLParser(HTMLParser):
    """
    解析https://sslbl.abuse.ch页面的表格
    """
    def __init__(self):
        super(SSLBLParser, self).__init__()
        self.results = []
        self.row = {}  # 每一行的内容
        self.flag = 0  # 是否在某一行内部
        self.colCount = 0  # 区分每一列
        self.dataType = {1: 'utc_time', 2: 'sha1', 3: 'link', 4: 'reason'}

    def handle_starttag(self, tag, attrs):
        if tag == 'tr' and len(attrs) > 0 and attrs[0][0] == 'bgcolor':
            self.flag = 1
        if tag == 'td' and self.flag:
            self.colCount += 1
        if self.flag and self.colCount == 2 and \
                tag == 'a' and len(attrs) > 0 and attrs[0][0] == 'href':
            self.row[self.dataType[3]] = SSLBL_URL + attrs[0][1]

    def handle_endtag(self, tag):
        global LAST_SHA1
        if tag == 'tr' and self.flag:
            if self.row['sha1'] == LAST_SHA1:
                raise ParseDoneException(self.results)
            self.flag = 0
            self.colCount = 0
            self.results.append(self.row)  # 写入一行
            self.row = {}

    def handle_data(self, data):
        if self.colCount == 1 or self.colCount == 2 or self.colCount == 4:
            self.row[self.dataType[self.colCount]] = data.strip()

    def get_results(self):
        return self.results


class SSLInfoParser(HTMLParser):
    """
    解析url结构为https://sslbl.abuse.ch/intel/sha1
    其中的ssl certificate info表格的内容
    """
    def __init__(self):
        super(SSLInfoParser, self).__init__()
        self.results = {}
        self.flag = 0  # 是否在表格内部
        self.inTD = 0  # 是否在<td>中
        self.colCount = 0  # 区分每一列
        self.dataType = {1: 'subject_name', 2: 'subject', 3: 'issuer_name', 4: 'issuer', 5: 'ssl_ver'}

    def handle_starttag(self, tag, attrs):
        if tag == 'table' and len(attrs) > 0 and attrs[0][1] == 'tlstable':
            self.flag = 1
        if self.flag and tag == 'td':
            self.inTD = 1
            self.colCount += 1

    def handle_endtag(self, tag):
        if tag == 'td' and self.inTD == 1:
            self.inTD = 0

    def handle_data(self, data):
        if self.inTD and 0 < self.colCount < 6:
            self.results[self.dataType[self.colCount]] = data.strip()

    def get_results(self):
        return self.results


class AssociatedMalwareParser(HTMLParser):
    """
    解析url结构为https://sslbl.abuse.ch/intel/sha1
    页面下方的associated malware binaries表格的内容
    """
    def __init__(self):
        super(AssociatedMalwareParser, self).__init__()
        self.results = []
        self.row = {}  # 每一行的内容
        self.flag = 0  # 是否在表格内部
        self.inTR = 0  # 是否在<tr>内部
        self.colCount = 0  # 区分每一列
        self.dataType = {1: 'utc_time', 2: 'md5', 3: 'dst_ip', 4: 'dst_port'}

    def handle_starttag(self, tag, attrs):
        if tag == 'table' and len(attrs) > 0 and attrs[0][1] == 'sortable':
            self.flag = 1
        if self.flag and tag == 'tr':
            self.inTR = 1
        if self.inTR and tag == 'td':
            self.colCount += 1

    def handle_endtag(self, tag):
        if tag == 'tr' and self.inTR:
            self.inTR = 0
            self.colCount = 0
            if self.row:  # 去掉<thead>中的信息
                self.results.append(self.row)  # 写入一行
            self.row = {}
        if self.flag and tag == 'table':
            self.flag = 0

    def handle_data(self, data):
        if 0 < self.colCount < 5:
            self.row[self.dataType[self.colCount]] = data.strip()

    def get_results(self):
        return self.results


class SSLBL(object):
    """
    下载并读取网页数据，写入数据库/查询数据库
    """
    def __init__(self):
        self.results = []

    @staticmethod
    def get_last_sha1():
        try:
            logger.info('try to get last sslbl sha1')
            with open(LAST_SHA1_PATH, 'rb') as f:
                last_sha1 = pickle.load(f)
                # print(last_sha1)
        except Exception:
            logger.error('last sha1 not found, read from backup', exc_info=True)
            shutil.copy(DATA_PATH + '/backup/last_sha1', LAST_SHA1_PATH)
            with open(LAST_SHA1_PATH, 'rb') as f:
                last_sha1 = pickle.load(f)
            # 下面是刚开始建立数据库时使用的, 目前不存在这种情况
            # logger.error('last sha1 not found, build an empty one', exc_info=True)
            # last_sha1 = ''
            # f = open(LAST_SHA1_PATH, 'wb')
            # pickle.dump(last_sha1, f)
        return last_sha1

    @staticmethod
    def write_last_sha1(sha1):
        try:
            logger.info('write last sslbl sha1 %s', sha1)
            with open(LAST_SHA1_PATH, 'wb') as f:
                pickle.dump(sha1, f)
        except Exception:
            print('写入last_sha1 %s 失败, 请之后手动写入.' % sha1)
            logger.error('write last sha1 failed.', exc_info=True)

    @staticmethod
    def if_download_main():
        now = datetime.now().timestamp()
        if not os.path.exists(SSLBL_PATH) or \
                now - os.stat(SSLBL_PATH).st_mtime > UPDATE_INTERVAL:
            return 1
        else:
            return 0

    @staticmethod
    def download_main():
        try:
            logger.info('downloading sslbl main page')
            main = request.urlopen(SSLBL_URL).read()
            with open(SSLBL_PATH, 'wb') as f:
                f.write(main)
            return 1
        except Exception:
            logger.error('sslbl main page download fail', exc_info=True)
            print('sslbl主页下载失败, 使用本地数据')
            return 0

    def download_sub(self):
        length = len(self.results)
        logger.info('sslbl sub pages download start, total %d', length)
        for i, result in enumerate(self.results):
            url = result['link']
            logger.info('sslbl sub pages downloading %d', i+1)
            logger.info('url: %s', url)
            f_name = result['utc_time'] + ' ' + result['sha1'] + ' ' + str(i)
            # 存在同名文件, 但并不会出现这种情况
            # if os.path.exists(TEMP_PATH + '/' + f_name):
            #     raise FileExistsError

            # 若需要确保下载大量文件时不会中断,则此处改为死循环
            # 实际使用中重试三次即可
            for retry in range(3):
                try:
                    content = request.urlopen(url).read()
                    with open(TEMP_PATH + '/' + f_name, 'wb') as f:
                        f.write(content)
                    break
                except Exception:
                    if retry == 2:
                        logger.error('download failed.', exc_info=True)
                        print('下载sslbl sub pages失败, 使用本地数据')
                        self.clear_temp()
                        return 0
                    else:
                        logger.error('download failed, retry...', exc_info=True)
            logger.info('sslbl sub pages %d done', i+1)
        logger.info('sslbl sub pages download complete')
        return 1

    def parse_main_local(self, path=SSLBL_PATH):
        parser = SSLBLParser()
        with open(path) as f:
            try:
                parser.feed(f.read())
                self.results = parser.get_results()
            except ParseDoneException as e:
                self.results = e.get_results()
        logger.info('main page parsed, %d new', len(self.results))

    def test_downloaded_sub(self):
        logger.info('checking downloaded files')
        for i, result in enumerate(self.results):
            f_name = result['utc_time'] + ' ' + result['sha1'] + ' ' + str(i)
            if os.path.exists(TEMP_PATH + '/' + f_name):
                continue
            else:
                logger.error('download incomplete, no %s', result['sha1'])
                return 0
        logger.info('check done')
        return 1

    @staticmethod
    def clear_temp(path=TEMP_PATH):
        # 只需要删第一层, 保留sslbl.html
        ls = os.listdir(path)
        for item in ls:
            f = os.path.join(path, item)
            if not os.path.isdir(f) and item != 'sslbl.html':
                os.remove(f)

    def download_handler(self):
        global LAST_SHA1
        LAST_SHA1 = self.get_last_sha1()
        if self.if_download_main():
            # 清空temp
            if os.listdir(TEMP_PATH):
                self.clear_temp()
            r1 = self.download_main()
            if not r1:
                return 0
        self.parse_main_local()

        if self.results:
            r2 = self.download_sub()
            if not r2:
                return 0
        # 检查下载的文件
        r3 = self.test_downloaded_sub()
        if not r3:
            return 0

        return 1

    @staticmethod
    def parse_sub_local(result, i):
        # 此函数执行前已经确保了文件存在
        f_name = result['utc_time'] + ' ' + result['sha1'] + ' ' + str(i)
        # print(f_name)
        path = TEMP_PATH + '/' + f_name
        info_p = SSLInfoParser()
        mal_p = AssociatedMalwareParser()
        with open(path) as f:
            html = f.read()
            info_p.feed(html)
            mal_p.feed(html)
        return info_p.get_results(), mal_p.get_results()

    def write_db(self):
        global LAST_SHA1

        session = Session()
        length = len(self.results)

        if self.results:
            logger.info('start writing data to db, total %d results', length)
            for i, result in enumerate(self.results):
                info, mal = self.parse_sub_local(result, i)
                # 各种变量
                utc = result['utc_time']
                sha1 = result['sha1']
                reason = result['reason']

                sub_name = info.get('subject_name', '')
                sub = info.get('subject', '')
                iss_name = info.get('issuer_name', '')
                iss = info.get('issuer', '')
                ver = info.get('ssl_ver', '')
                # 新建证书
                new_certificate = Certificate(utc_time=utc, sha1=sha1, reason=reason, subject_common_name=sub_name,
                                              subject=sub, issuer_common_name=iss_name, issuer=iss, ssl_ver=ver)
                session.add(new_certificate)
                # 新建IP
                for ip in mal:
                    time = ip.get('utc_time', '')
                    md5 = ip.get('md5', '')
                    d_ip = ip.get('dst_ip', '')
                    port = ip.get('dst_port', '')

                    new_ip = IP(utc_time=time, md5=md5, dst_ip=d_ip, dst_port=port, certificate_sha1=sha1)
                    session.add(new_ip)
                logger.info('add %d to db', i+1)
            # 完成
            session.commit()
            # 写入此次更新的位置
            LAST_SHA1 = self.results[0]['sha1']
            self.write_last_sha1(LAST_SHA1)
            # 备份当前LAST_SHA1
            shutil.copy(LAST_SHA1_PATH, DATA_PATH + '/backup/last_sha1')

            logger.info('delete temp files')
            self.clear_temp()
            logger.info('ssldb data updated success')

        session.close()

    @staticmethod
    def read_db(kw, mode):
        # mode: 1 for IP, 2 for certificate name/domain, 3 for SHA1
        results = []  # 最终结果
        single = {}  # 单条记录
        rs = []  # 查询结果对象
        session = Session()
        # 从IP查询
        if mode == 1:
            rs = session.query(IP).filter(IP.dst_ip == kw).all()
            # print(rs)
            for r in rs:
                single['utc_time'] = r.utc_time
                single['md5'] = r.md5
                single['ip'] = r.dst_ip
                single['port'] = r.dst_port
                single['certificate_sha1'] = r.certificate_sha1
                results.append(single)
                single = {}
        # 从证书查询
        else:
            if mode == 2:
                kw = '%' + kw + '%'
                rs1 = session.query(Certificate).filter(Certificate.subject_common_name.like(kw)).all()
                rs2 = session.query(Certificate).filter(Certificate.subject.like(kw)).all()
                rs3 = session.query(Certificate).filter(Certificate.issuer_common_name.like(kw)).all()
                rs4 = session.query(Certificate).filter(Certificate.issuer.like(kw)).all()
                # print(rs1, rs2, rs3, rs4)
                rs = list(set(rs1) | set(rs2) | set(rs3) | set(rs4))
            if mode == 3:
                rs = session.query(Certificate).filter(Certificate.sha1 == kw).all()

            for r in rs:
                # 证书信息
                single['utc_time'] = r.utc_time
                single['sha1'] = r.sha1
                single['subject_common_name'] = r.subject_common_name
                single['subject'] = r.subject
                single['issuer_common_name'] = r.issuer_common_name
                single['issuer'] = r.issuer
                single['ssl_ver'] = r.ssl_ver
                single['reason'] = r.reason
                # 关联的IP
                ips = r.ips
                single['ips'] = []  # 由多个single_ip组成
                single_ip = {}
                for ip in ips:
                    single_ip['utc_time'] = ip.utc_time
                    single_ip['md5'] = ip.md5
                    single_ip['ip'] = ip.dst_ip
                    single_ip['port'] = ip.dst_port
                    single['ips'].append(single_ip)
                    single_ip = {}
                results.append(single)
                single = {}

        session.close()
        return results
