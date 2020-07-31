import requests
import logging


VT_API_KEY = 'c5e2964b62a5513d17a73f66148b3a23c3b168af0a60bcfb3ce0b5f683bedb0f'
VT_IP_URL = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
VT_DOMAIN_URL = 'https://www.virustotal.com/vtapi/v2/domain/report'
# VT_URL_URL = 'https://www.virustotal.com/vtapi/v2/url/report'

logger = logging.getLogger('main')


class VirusTotal(object):
    """
    搜索VirusTotal并得到结果（只能搜索域名及IP)
    和shodan一样, 提供一个简化的结果用于输出excel表格
    """
    def __init__(self, kw, kw_type):
        self.kw = kw
        self.kw_type = kw_type  # 0为域名, 1为IP
        self.params = {'apikey': VT_API_KEY}
        self.results = {}

    def search(self):
        try:
            logger.info('start searching virustotal')
            if self.kw_type == 0:
                self.params['domain'] = self.kw
                self.results = requests.get(VT_DOMAIN_URL, self.params).json()
            elif self.kw_type == 1:
                self.params['ip'] = self.kw
                self.results = requests.get(VT_IP_URL, self.params).json()

            res_code = self.results['response_code']
            if res_code != 1:
                if res_code == 0 or res_code == -2:
                    print('从virustotal未查询到结果')
                else:
                    print('从virustotal查询出错,请查询日志')
                logger.error('search from virustotal failed')
                logger.error('err_code: ' + str(self.results['response_code'])
                             + '\nmsg: ' + str(self.results['verbose_msg']))
        except Exception:
            print('从virustotal查询出错')
            logger.error('search from virustotal failed', exc_info=True)

    def get_result(self):
        return self.results

    def get_simple_results(self):
        simple_results = {}
        # ip
        if self.kw_type == 1 and self.results['response_code'] == 1:
            simple_results['asn'] = self.results.get('asn', '')
            simple_results['country'] = self.results.get('country', '')
            simple_results['resolutions'] = []
            simple_results['detected_urls'] = []
            simple_results['detected_downloaded_samples'] = []

            for r in self.results.get('resolutions', []):
                simple_results['resolutions'].append(r.get('hostname', ''))

            for r in self.results.get('detected_urls', []):
                simple_results['detected_urls'].append(r.get('url', ''))

            for r in self.results.get('detected_downloaded_samples', []):
                simple_results['detected_downloaded_samples'].append(r.get('sha256', ''))

            simple_results['undetected_urls'] = len(self.results.get('undetected_urls', []))
            simple_results['undetected_downloaded_samples'] = len(self.results.get('undetected_downloaded_samples', []))

        # 域名
        elif self.kw_type == 0 and self.results['response_code'] == 1:
            simple_results['subdomains'] = self.results.get('subdomains', [])
            simple_results['categories'] = self.results.get('categories', [])
            simple_results['domain_siblings'] = self.results.get('domain_siblings', [])
            simple_results['resolutions'] = []
            simple_results['detected_urls'] = []
            simple_results['detected_referrer_samples'] = []
            simple_results['detected_downloaded_samples'] = []

            for r in self.results.get('resolutions', []):
                simple_results['resolutions'].append(r.get('ip_address', ''))

            for r in self.results.get('detected_urls', []):
                simple_results['detected_urls'].append(r.get('url', ''))

            for r in self.results.get('detected_referrer_samples', []):
                simple_results['detected_referrer_samples'].append(r.get('sha256', ''))

            for r in self.results.get('detected_downloaded_samples', []):
                simple_results['detected_downloaded_samples'].append(r.get('sha256', ''))

            simple_results['undetected_urls'] = len(self.results.get('undetected_urls', []))
            simple_results['undetected_referrer_samples'] = len(self.results.get('undetected_referrer_samples', []))
            simple_results['undetected_downloaded_samples'] = len(self.results.get('undetected_downloaded_samples', []))

        return simple_results
