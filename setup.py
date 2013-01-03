#!/usr/bin/python
import urlsniffer
from distutils.core import setup
setup(name='urlsniffer',
      version=urlsniffer.__version__,
      description='Url sniffing daemon',
      license='GNU GPL2',
      author='Mete Alpaslan Katircioglu',
      author_email='mete@katircioglu.net',
      url='http://mkatircioglu.github.com',
      packages=['urlsniffer'],
      data_files=[('/etc', ['data/urlsniffer.conf']),
                  ('/etc/logrotate.d', ['data/urlsniffer']),
                  ('/etc/init.d', ['data/urlsnifferd'])],
      scripts=['bin/urlsniffer'],
      requires=['pcapy (>=0.10.5)', 'Impacket (>=0.9.6)']
     )
