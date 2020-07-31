from setuptools import setup, find_packages

VERSION = '0.2'

setup(name='SecuritySitesQuery',
      version=VERSION,
      packages=find_packages(),
      description="A cli tool for searching the websites on security, you can query for ips/domains/ssl certificates.",
      long_description="""websites supported:
      https://www.shodan.io
      https://zeustracker.abuse.ch/blocklist.php
      https://sslbl.abuse.ch
      https://www.malwaredomainlist.com
      https://www.virustotal.com""",
      install_requires=[
          'sqlalchemy',
          'click',
          'xlsxwriter',
          'shodan',
          'requests',
      ],
      include_package_data=True,
      entry_points={
          'console_scripts': ['ssq = query_app.sites_query:main']
      }
      )
