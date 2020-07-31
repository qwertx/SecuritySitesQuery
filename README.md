# SecuritySitesQuery

一个用来搜索安全相关网站的命令行小工具，可以查询IP地址、域名、SSL证书

查询结果可以选择直接显示、导出为json或excel表格

支持同时查询以下五个网站：

https://www.shodan.io, 以下简称为shodan

https://www.virustotal.com, 以下简称为virustotal

https://www.malwaredomainlist.com, 以下简称为malware

https://sslbl.abuse.ch, 以下简称为sslbl

https://zeustracker.abuse.ch/blocklist.php, 以下简称为zeustracker

其中前三个网站为在线查询，后两个会在查询前将数据更新到本地后查询

## 使用

程序在 Python 3 下执行， 需要先安装好 setuptools

第三方依赖包(自动安装): shodan, sqlalchemy, click, xlsxwriter, requests

```bash
# 安装
python3 setup.py install
# 第一次使用需要指定输出路径
# 搜索全部五个网站，将结果导出为json和excel
ssq seu.edu.cn
# 不更新, 仅搜索ZeusTracker, 仅导出json
ssq bright.su 4 -u 0 -o 1
# 指定关键词为IP，仅搜索Shodan和MDL，仅导出xlsx表格
ssq 104.27.163.228 1 2 -m 1 -o 2
# 仅搜索SSLBL, 导出json和excel到, 文件名为output
ssq izqertuiwt.biz 3 -n output
# 搜索证书的sha1码, 输出结果到控制台
ssq e0d903bbddc642e5f7820b22d86eae9e15a7b2f8 -o 3
```

## 数据格式

由于五个网站提供的数据格式各不相同，下面对其做一个简单的介绍

#### Shodan

搜索域名时API返回的搜索结果结构为
```
{
    'total': 数目,
    'matches': [搜索结果列表]
}
```

由于返回的原结果比较复杂，为了便于阅读，简化为如下结构  
输出时会保留一份原结果供查阅
```
{
    "asn": "AS21183",
    "domains": [
        "abcom.al"
    ],
    "hostnames": [
        "ptr.abcom.al"
    ],
    "ip_str": "217.73.133.213",
    "isp": "ABCOM Shpk",
    "org": "ABCOM Shpk",
    "port": 8081,
    "timestamp": "2018-09-17T14:44:37.999984",
    "transport": "tcp",
    "product": "MikroTik http proxy",
    "version": "",
    "module": "https-simple-new",
    "country": "Albania",
    "city": "Tirana",
    "vulns": []
}
```

搜索IP时结果简化为如下格式
```
{
    "asn": "AS20473",
    "city": "Heiwajima",
    "country_name": "Japan",
    "hostnames": [
        "45.76.199.74.vultr.com"
    ],
    "ip_str": "45.76.199.74",
    "isp": "Choopa, LLC",
    "last_update": "2018-09-11T10:42:49.102075",
    "org": "Choopa, LLC",
    "ports": [
        80,
        123
    ],
    "vulns": "",
    "tags": [],
    "module": [
        "http",
        "ntp"
    ]
}
```

#### VirusTotal

网站本身支持多种搜索，但此程序目前仅支持IP和域名搜索，每分钟最多搜索4次  
API返回一个字典，包含了以下的key

搜索IP时:  
asn: Autonomous system number  
country: guess on what country it is in  
resolutions: Hostnames that this IP address resolves to and the date  
detected_urls: URLs at this IP address that have at least 1 detection on a URL scan  
detected_downloaded_samples: Files that have been downloaded from this IP address with at least one AV detection  
undetected_downloaded_samples: Files that have been downloaded from this IP address with zero AV detections  
undetected_urls: URLs at this IP address with no detections on a URL scan.  

搜索域名时：  
提供了subdomains,categories,domain_siblings,resolutions,  
detected_urls,detected_referrer_samples,detected_downloaded_samples,  
undetected_urls,undetected_referrer_samples,undetected_downloaded_samples这10项  
以及一些其他信息

和shodan一样，提供简化版本的搜索结果  
在表格和简化版的搜索结果中，对于undetected的项目只显示数目

#### Malware

对列入黑名单的域名，提供了时间，域名，IP，Reverse Lookup，描述，ASN，国家等信息  
由于是在线搜索并爬取结果页面，因此可以搜索其中任意项

#### SSLBL

对每一个列入黑名单的证书，提供了列入时间, sha1, 签发者, 持有者, ssl版本等信息

每个证书额外提供了一个Associated malware binaries列表  
列出了相关的time, MD5, dstIP, dstPort

支持搜索sha1, 证书subject和issuer名称, 以及从malware列表里搜索IP


#### ZeusTracker

只提供了5个黑名单，网站上的描述如下，本程序将搜索所有5个列表并提供列表名称：

##### zeus_domain_recommended:  

If you want to block domain names used by the ZeuS trojan, you should use this list.   
The ZeuS domain blocklist (BadDomains) is the recommended blocklist if you want to block only ZeuS domain names.  
It excludes domain names that ZeuS Tracker believes to be hijacked (level 2).  
Hence the false positive rate should be much lower compared to the standard ZeuS domain blocklist.

##### zeus_domain_standard:  

This blocklist contains the same data as the ZeuS domain blocklist (BadDomains) but with the slight difference that it doesn't exclude hijacked websites (level 2).  
This means that this blocklist contains all domain names associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker.  
Hence this blocklist will likely cause some false positives.

##### zeus_ip_recommended:  

This blocklists only includes IPv4 addresses that are used by the ZeuS trojan.   
It is the recommened blocklist if you want to block only ZeuS IPs.  
It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3).  
Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. 

##### zeus_ip_standard:  

This blocklist contains the same data as the ZeuS IP blocklist (BadIPs) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3).  
This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cswhich are currently being tracked by ZeuS Tracker.  
Hence this blocklist will likely cause some false positives.

##### zeus_url_compromised:  

This blocklist only contains compromised / hijacked websites (level 2) which are being abused by cybercriminals to host a ZeuS botnet controller. 
Since blocking the FQDN or IP address of compromised host would cause a lot of false positives, the ZeuS compromised URL blocklist contains the full URL to the ZeuS config, dropzone or malware binary instead of the FQDN / IP address.

## 输出内容

根据输出模式的不同，可以同时或单独输出为excel和json，也可以选择输出到控制台  
当在shodan或virustotal中查询到结果时，会额外提供一个简化版的搜索模式

最终输出格式如下
```
# 搜索IP
{
    "shodan": {
        "asn": "AS20473",
        "city": "Heiwajima",
        "country_name": "Japan",
        "hostnames": [
            "45.76.199.74.vultr.com"
        ],
        "ip_str": "45.76.199.74",
        "isp": "Choopa, LLC",
        "last_update": "2018-09-11T10:42:49.102075",
        "org": "Choopa, LLC",
        "ports": [
            80,
            123
        ],
        "vulns": "",
        "tags": [],
        "module": [
            "http",
            "ntp"
        ]
    },
    "sslbl": [
        {
            "utc_time": "2018-09-14 11:52:12",
            "md5": "c7d6e5f214fe6876c90cabf3f02f1d69",
            "ip": "47.74.44.209",
            "port": 443,
            "certificate_sha1": "d33298d1fe3d43ecc087c2883fba8a6cc124c42e"
        },
    ],
    "virustotal": {
        "asn": "",
        "country": "CA",
        "resolutions": [
            "bibonado.com",
        ],
        "detected_urls": [
            "https://rocknrolletco.top",
        ],
        "detected_downloaded_samples": [
            "ea4373cf2a3c774dac014a0d78cf09b1f6b23b15c2130455071cd7375bb5d7e2",
        ],
        "undetected_urls": 0,
        "undetected_downloaded_samples": 4
    },
    "zeus": {
        "ip_recommended": [
            "101.200.81.187"
        ],
    "malware": [
        {
            "Date(UTC)": "2017/12/04_18:50",
            "Domain": "textspeier.de",
            "IP": "104.27.163.228",
            "Reverse Lookup": "",
            "Description": "phishing/fraud",
            "ASN": "13335",
            "Country": "United States"
        }
    ]
}
# 搜索域名
{
    "shodan": {
        "total": 1,
        "matches": [
            {
                "asn": "AS4538",
                "domains": [
                    "seu.edu.cn"
                ],
                "hostnames": [
                    "wpidc121.seu.edu.cn"
                ],
                "ip_str": "121.248.63.121",
                "isp": "China Education and Research Network",
                "org": "Southeast University",
                "port": 80,
                "timestamp": "2018-09-17T22:15:35.529150",
                "transport": "tcp",
                "product": "Apache httpd",
                "version": "2.4.25",
                "module": "http",
                "country": "China",
                "city": "Nanjing",
                "vulns": [
                    "CVE-2017-7679",
                ]
            },
    "zeus": {
        "domain_recommended": [
            "bright.su"
        ],
    "virustotal": {
        "subdomains": [
            "atc.seu.edu.cn",
            "jwc.seu.edu.cn",
        ],
        "categories": [
            "education",
            "educational institutions"
        ],
        "domain_siblings": [
            "ae.gdufe.edu.cn",
        ],
        "resolutions": [
            "121.248.63.50",
            "121.248.63.91"
        ],
        "detected_urls": [
            "http://seu.edu.cn/_upload/article/c2/c7/3c0f44ed4e379ff820776b365c32/b518f630-caa7-4f0e-b85d-ac60e34394c5.doc",
            "http://seu.edu.cn/_upload/article/c2/c7/3c0f44ed4e379ff820776b365c32/9d41cf4d-5fa2-418a-9824-d5e375a62cc0.doc"
        ],
        "detected_referrer_samples": [
            "4e0422a75278b146ba0d0bfea5bd290ac7de9fed68881cf21d4a57d9f0f3d566"
        ],
        "detected_downloaded_samples": [
            "380373dace39948ceadc6e8e8f805ebad7e6987866eab3670c8ec1412a87a41f",
            "31cf1a6dffb750c8b24e8a79cc85d86e63658ea42a561d8c2f9d738c7bcbeb4a"
        ],
        "undetected_urls": 0,
        "undetected_referrer_samples": 100,
        "undetected_downloaded_samples": 1
    }
# 搜索证书
{
    "sslbl": [
        {
            "utc_time": "2018-09-15 13:36:39",
            "sha1": "d33298d1fe3d43ecc087c2883fba8a6cc124c42e",
            "subject_common_name": "rocknrolletco.top",
            "subject": "CN=rocknrolletco.top",
            "issuer_common_name": "Let's Encrypt Authority X3",
            "issuer": "C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3",
            "ssl_ver": "TLS 1.2",
            "reason": "Smoke Loader C&C",
            "ips": [
                {
                    "utc_time": "2018-09-14 11:52:12",
                    "md5": "c7d6e5f214fe6876c90cabf3f02f1d69",
                    "ip": "47.74.44.209",
                    "port": 443
                },
                {
                    "utc_time": "2018-09-13 05:52:45",
                    "md5": "2a0aa36717c8f404a4d2a0c07110d112",
                    "ip": "47.74.44.209",
                    "port": 443
                }
            ]
        }
    ]
}
```

## 最近更新时间

 - Update 20180815 : 初步完成，版本0.1
 - Update 20180915 : 加入对virustotal.com的查询, 修复了证书验证和输出路径等问题




