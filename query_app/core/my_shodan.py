import shodan
import logging
from shodan.exception import APIError

SHODAN_API_KEY = 'xxx
logger = logging.getLogger('main')


class MyShodan(object):
    """
    搜索shodan并得到结果
    由于shodan返回的数据太复杂, 将额外提供一个简化的版本
    """
    def __init__(self):
        self.api = shodan.Shodan(SHODAN_API_KEY)
        self.results = {}

    def search(self, kw, kw_type):
        try:
            if kw_type == 1:
                logger.info('start search shodan, type: ip')
                try:
                    self.results = self.api.host(kw)
                except APIError:
                    logger.error('no results from shodan', exc_info=True)
                # print(self.results)
            if kw_type != 1 or self.results == {}:
                logger.info('start searching shodan')
                try:
                    self.results = self.api.search(kw)
                except APIError:
                    logger.error('no results from shodan', exc_info=True)
                # print(self.results)
                # 结果太多的处理, 应该较少用到
                if self.results.get('total', 0) > 1000:
                    print('shodan搜索结果过多, 取前1000项')
                    logger.info('too many results, choose the preceding 1000')
                    matches = self.results['matches'][:1000]
                    self.results['matches'] = matches
                    self.results['total'] = 1000
        except Exception:
            print('从shodan查询出错')
            logger.error('search from shodan failed', exc_info=True)
        return self.results

    @staticmethod
    def get_results_module(item):
        try:
            module = item['_shodan']['module']
        except Exception:
            logger.error('cannot get shodan module info', exc_info=True)
            module = ''
        return module

    def get_simple_results(self, kw_type):
        # 简化shodan的搜索结果, 用于输出excel表格
        simple_results = {}
        if kw_type == 1 and self.results and 'total' not in self.results:
            simple_results['asn'] = self.results.get('asn', '')
            simple_results['city'] = self.results.get('city', '')
            simple_results['country_name'] = self.results.get('country_name', '')
            simple_results['hostnames'] = self.results.get('hostnames', '')
            simple_results['ip_str'] = self.results.get('ip_str', '')
            simple_results['isp'] = self.results.get('isp', '')
            simple_results['last_update'] = self.results.get('last_update', '')
            simple_results['org'] = self.results.get('org', '')
            simple_results['ports'] = self.results.get('ports', '')
            simple_results['vulns'] = self.results.get('vulns', '')
            simple_results['tags'] = self.results.get('tags', '')

            simple_results['module'] = []
            data = self.results.get('data', '')
            if data:
                for item in data:
                    module = self.get_results_module(item)
                    simple_results['module'].append(module)

        if 'total' in self.results and self.results['total'] != 0:
            simple_results['total'] = self.results['total']
            simple_results['matches'] = []
            for item in self.results['matches']:
                simple_item = {}
                simple_item['asn'] = item.get('asn', '')
                simple_item['domains'] = item.get('domains', '')
                simple_item['hostnames'] = item.get('hostnames', '')
                simple_item['ip_str'] = item.get('ip_str', '')
                simple_item['isp'] = item.get('isp', '')
                simple_item['org'] = item.get('org', '')
                simple_item['port'] = item.get('port', '')
                simple_item['timestamp'] = item.get('timestamp', '')
                simple_item['transport'] = item.get('transport', '')
                simple_item['product'] = item.get('product', '')
                simple_item['version'] = item.get('version', '')

                simple_item['module'] = self.get_results_module(item)
                location = item.get('location', {})
                simple_item['country'] = location.get('country_name', '')
                simple_item['city'] = location.get('city', '')
                vulns = item.get('vulns', {})
                vu = []
                for k in vulns.keys():
                    vu.append(k)
                simple_item['vulns'] = vu

                simple_results['matches'].append(simple_item)

        return simple_results

# s = MyShodan()
# s.search('6.6.6.6', 1)
# print(s.results)
