import os
import logging
import json
import xlsxwriter
from pprint import pprint
from copy import deepcopy
from query_app.config import CONFIG
from query_app.core.malware import MalwareSearch
from query_app.core.zeus import Zeus
from query_app.core.zeus import LISTS
from query_app.core.sslbl import SSLBL
from query_app.core.my_shodan import MyShodan
from query_app.core.virustotal import VirusTotal


# 写入excel表格用的列标题
MALWARE_COL = ['Date(UTC)', 'Domain', 'IP', 'Reverse Lookup', 'Description', 'ASN', 'Country']


SSLBL_IP_COL = ['utc_time', 'ip', 'port', 'md5', 'certificate_sha1']
SSLBL_CERTIFICATE_COL = ['utc_time', 'sha1', 'subject', 'subject_common_name',
                         'issuer', 'issuer_common_name', 'ssl_ver', 'reason']
SSLBL_ASSOCIATES_COL = ['utc_time', 'ip', 'port', 'md5']


# ports, hostnames, module, vulns, tags为列表
SHODAN_IP_COL = ['ip_str', 'hostnames', 'ports', 'module', 'asn', 'country_name', 'city',
                 'isp', 'org', 'vulns', 'last_update', 'tags']

# domains, hostnames, vulns为列表
SHODAN_COL = ['ip_str', 'hostnames', 'domains', 'port', 'module', 'asn', 'country', 'city',
              'isp', 'org', 'vulns', 'transport', 'timestamp', 'product', 'version']


VT_IP_COL = ['asn', 'country', 'resolutions', 'detected_urls', 'detected_downloaded_samples',
             'undetected_urls', 'undetected_downloaded_samples']
VT_DOMAIN_COL = ['subdomains', 'categories', 'domain_siblings', 'resolutions',
                 'detected_urls', 'detected_referrer_samples', 'detected_downloaded_samples',
                 'undetected_urls', 'undetected_referrer_samples', 'undetected_downloaded_samples']


logger = logging.getLogger('main')


class QueryClient(object):
    """
    查询逻辑
    """
    def __init__(self):
        self.kw = CONFIG['keyword']
        self.site = CONFIG['site']
        self.mode = CONFIG['mode']
        self.update = CONFIG['update']
        self.output = CONFIG['output']
        self.f_name = CONFIG['name']
        self.path = CONFIG['path']

        self.json_path = self.path + '/' + self.f_name + '.json'
        self.xlsx_path = self.path + '/' + self.f_name + '.xlsx'
        self.simple_json_path = self.path + '/simple_' + self.f_name + '.json'

        # 定位写入excel表格的行和列
        self.row = 0
        self.col = 0

        if 1 in self.site:
            self.sd = MyShodan()
            self.sd_result = {}
            self.simple_result = {}
        if 2 in self.site:
            self.mal = MalwareSearch()
            self.mal_result = []
        if 3 in self.site:
            self.ssl = SSLBL()
            self.ssl_result = []
        if 4 in self.site:
            self.zeus = Zeus(self.kw, 1 if self.mode == 1 else 0)
            self.zeus_result = {}
        if 5 in self.site:
            self.vt = VirusTotal(self.kw, 1 if self.mode == 1 else 0)
            self.vt_result = {}
            self.vt_simple_result = {}

    def download(self):
        if 3 in self.site:
            print('正在从SSLBL下载...')
            r = self.ssl.download_handler()
            if r:
                try:
                    self.ssl.write_db()
                except Exception:
                    logger.error('write ssldb error', exc_info=True)
                    print('向sslbl.db写入数据错误, 将使用原有数据查询')
        if 4 in self.site:
            print('正在从ZeusTracker下载...')
            self.zeus.if_download()

    def search(self):
        if 1 in self.site and self.mode != 3:
            print('正在查询shodan...')
            self.sd_result = self.sd.search(self.kw, self.mode)
            self.simple_result = self.sd.get_simple_results(self.mode)
            # 统计记录数
            if self.simple_result:
                if self.mode == 1 and 'total' not in self.simple_result:
                    print('查询到此IP')
                elif 'total' in self.simple_result:
                    print('查询到%d条记录' % self.simple_result['total'])
            else:
                print('未找到记录')

        if 2 in self.site and self.mode != 3:
            print('正在查询malware...')
            self.mal_result = self.mal.search(self.kw)
            print('查询到%d条记录' % len(self.mal_result))

        if 3 in self.site:
            print('正在查询sslbl...')
            try:
                self.ssl_result = self.ssl.read_db(self.kw, self.mode)
            except Exception:
                logger.error('error occured when query from sslbl.db', exc_info=True)
                print('从sslbl.db查询出错')
            print('查询到%d条记录' % len(self.ssl_result))

        if 4 in self.site and self.mode != 3:
            print('正在查询zeustracker...')
            self.zeus_result = self.zeus.search()
            # 统计记录数
            counts = 0
            for v in self.zeus_result.values():
                counts += len(v)
            print('在%d个列表中查询到%d条记录' % (len(self.zeus_result), counts))

        if 5 in self.site and self.mode != 3:
            print('正在查询virustotal...')
            self.vt.search()
            self.vt_result = self.vt.get_result()
            self.vt_simple_result = self.vt.get_simple_results()
            if self.vt_simple_result != {}:
                print('查询到记录')

    def if_zeus(self):
        # 此函数用来判断是否从zeustracker查询到结果
        for k in self.zeus_result.keys():
            if self.zeus_result[k]:
                return True
        return False

    def write_line(self, sheet, col_name, row_data, bold, if_title):
        # col_name为表格每一列的标题list, row_data为一行的内容dict, 其key为col_name中的内容
        # 将row_data按照col_name的顺序写入excel, 并移到下一行首个单元格

        # 写入标题行, 字体加粗
        if if_title:
            for item in col_name:
                sheet.write(self.row, self.col, item, bold)
                self.col += 1
        # 内容行
        else:
            if col_name:
                for item in col_name:
                    sheet.write(self.row, self.col, str(row_data[item]))
                    self.col += 1
            # 若col_name为空
            else:
                for item in row_data:
                    sheet.write(self.row, self.col, item)
                    self.col += 1
        self.row += 1
        self.col = 0

    def write_vt_line(self, sheet, col_name, row_data):
        # 用于写入virustotal的数据, 和write_line基本相同
        # 特点是结果的value中有长列表
        for item in col_name:
            if isinstance(row_data[item], list):
                for i in row_data[item]:
                    i = i[:250]
                    sheet.write(self.row, self.col, i)
                    self.row += 1
                self.row -= len(row_data[item])
            else:
                sheet.write(self.row, self.col, row_data[item])
            self.col += 1
        self.row += 1
        self.col = 0

    def result_to_xlsx(self):
        # 每次查询生成一个excel表格
        # 写入excel表的顺序: zeus, malware, sslbl, shodan, virustotal
        # 将内容简单的放在前面方便阅读
        workbook = xlsxwriter.Workbook(self.xlsx_path)
        worksheet = workbook.add_worksheet('query_results')
        bold = workbook.add_format({'bold': True})

        # zeustracker
        if 4 in self.site and self.if_zeus():
            worksheet.write(self.row, self.col, 'ZeusTracker', bold)
            self.row += 1
            for k in self.zeus_result.keys():
                # Zeustracker提供了5个list, 每一行为一个list中的检索结果
                # 重复的结果已经被剔除
                if self.zeus_result[k]:
                    # 使用行标题, 第一列为检索到结果的list名称
                    worksheet.write(self.row, self.col, LISTS[k], bold)
                    self.col += 1
                    self.write_line(worksheet, [], self.zeus_result[k], bold, 0)
            # 空2行为了阅读方便, 下同
            self.row += 2

        # malware
        if 2 in self.site and self.mal_result:
            worksheet.write(self.row, self.col, 'Malware', bold)
            self.row += 1
            # 写入列标题, 共7列
            self.write_line(worksheet, MALWARE_COL, [], bold, 1)
            # 写入malware结果
            for result in self.mal_result:
                self.write_line(worksheet, MALWARE_COL, result, bold, 0)
            self.row += 2

        # sslbl
        if 3 in self.site and self.ssl_result:
            worksheet.write(self.row, self.col, 'SSLBL', bold)
            self.row += 1
            # 查询的是IP
            if self.mode == 1:
                # 写入列标题
                self.write_line(worksheet, SSLBL_IP_COL, [], bold, 1)
                # 写入结果
                for result in self.ssl_result:
                    self.write_line(worksheet, SSLBL_IP_COL, result, bold, 0)
            # 查询非IP, 此时每个结果由一行证书信息和一张相关的IP表组成
            # 每个结果间会空一行
            else:
                # 写入列标题SSLBL_CERTIFICATE_COL
                self.write_line(worksheet, SSLBL_CERTIFICATE_COL, [], bold, 1)
                # 写入列标题SSLBL_ASSOCIATES_COL
                self.write_line(worksheet, SSLBL_ASSOCIATES_COL, [], bold, 1)
                # 空一行
                self.row += 1
                # 写入查询结果
                for result in self.ssl_result:
                    # 证书信息
                    self.write_line(worksheet, SSLBL_CERTIFICATE_COL, result, bold, 0)
                    # 相关IP表
                    ips = result.get('ips', '')
                    for ip in ips:
                        self.write_line(worksheet, SSLBL_ASSOCIATES_COL, ip, bold, 0)
                    # 空一行
                    self.row += 1
            self.row += 2

        # shodan
        if 1 in self.site and self.simple_result:
            if self.mode == 1 and 'total' not in self.simple_result:
                worksheet.write(self.row, self.col, 'Shodan', bold)
                self.row += 1
                # 写入列标题
                self.write_line(worksheet, SHODAN_IP_COL, [], bold, 1)
                # 写入数据
                self.write_line(worksheet, SHODAN_IP_COL, self.simple_result, bold, 0)
            elif 'total' in self.simple_result:
                worksheet.write(self.row, self.col, 'Shodan', bold)
                # 写入搜索结果总数
                self.col += 1
                worksheet.write(self.row, self.col, 'total: ' + str(self.simple_result['total']), bold)
                # 下一行
                self.col = 0
                self.row += 1
                # 写入列标题
                self.write_line(worksheet, SHODAN_COL, [], bold, 1)
                # 写入数据
                for item in self.simple_result['matches']:
                    self.write_line(worksheet, SHODAN_COL, item, bold, 0)
            self.row += 2

        # virustotal
        if 5 in self.site and self.vt_result['response_code'] == 1:
            worksheet.write(self.row, self.col, 'VirusTotal', bold)
            self.row += 1
            # IP
            if self.mode == 1:
                self.write_line(worksheet, VT_IP_COL, [], bold, 1)
                self.write_vt_line(worksheet, VT_IP_COL, self.vt_simple_result)
            else:
                self.write_line(worksheet, VT_DOMAIN_COL, [], bold, 1)
                self.write_vt_line(worksheet, VT_DOMAIN_COL, self.vt_simple_result)

        workbook.close()
        logger.info('results have written to excel')

    def merge_results(self):
        # 将搜索结果合并为一个dict, 返回一个2元素的列表, 包含了完整版和简化版的结果
        merged_normal = {}

        if 2 in self.site and self.mal_result:
            merged_normal['malware'] = self.mal_result
        if 3 in self.site and self.ssl_result:
            merged_normal['sslbl'] = self.ssl_result
        if 4 in self.site and self.if_zeus():
            zeus_r = {}
            for k, v in self.zeus_result.items():
                if v:
                    zeus_r[LISTS[k]] = v
            merged_normal['zeus'] = zeus_r

        c1 = 1 in self.site and self.simple_result
        c2 = 5 in self.site and self.vt_simple_result
        if c1 or c2:
            # 此处要用深拷贝, 不能直接赋值！
            merged_simple = deepcopy(merged_normal)
            if c1:
                merged_normal['shodan'] = self.sd_result
                merged_simple['shodan'] = self.simple_result
            if c2:
                merged_normal['virustotal'] = self.vt_result
                merged_simple['virustotal'] = self.vt_simple_result
            return [merged_normal, merged_simple]

        return [merged_normal, {}]

    def result_to_json(self, merged):
        # merged是merge_results的返回值
        # 输出简化的json
        if merged[1]:
            with open(self.simple_json_path, 'w') as f:
                f.write(json.dumps(merged[1], indent=4))
        # 输出完整的json
        if merged[0]:
            with open(self.json_path, 'w') as f:
                f.write(json.dumps(merged[0], indent=4))
            logger.info('results have written to json')
            print('已写入json文件')
        else:
            logger.error('no search results')

    def overall_output(self):
        # 当output模式为3时, 仅输出简化版的shodan搜索结果
        try:
            merged = self.merge_results()
            # 输出json
            if self.output == 0 or self.output == 1:
                self.result_to_json(merged)
            # 输出excel
            if self.output == 0 or self.output == 2:
                self.result_to_xlsx()
            # 输出到控制台
            if self.output == 3:
                print('result:')
                if merged[1]:
                    pprint(merged[1])
                elif merged[0]:
                    pprint(merged[0])
                else:
                    print('no results.')
        except Exception:
            logger.error('output error', exc_info=True)
            print('输出中出现错误, 请检查日志')

    def start(self):
        if self.update:
            self.download()
        self.search()
        self.overall_output()
        # 删除空的excel文件
        # 如果输出模式为2(仅输出excel), 则以下代码无效
        # 此时必定会生成一个excel文件, 若为空文件则需要手动删除
        if self.output != 2 and not os.path.exists(self.json_path):
            if os.path.exists(self.xlsx_path):
                os.remove(self.xlsx_path)
        elif self.output != 1 and os.path.exists(self.xlsx_path):
            print('已写入excel文件')
        logger.info('query complete.')
