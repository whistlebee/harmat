from __future__ import unicode_literals
from __future__ import print_function
from __future__ import division
from __future__ import absolute_import
#setup file

from builtins import open
from future import standard_library
standard_library.install_aliases()
from codecs import open
from os import path

from setuptools import setup, find_packages

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()


setup(
        name = 'sample',
        version = '0.2',
        description = 'HARMAT project',
        url='https://www.bitbucket.org/whistlebee/harmat',
        author = 'Paul Kim',
        author_email = 'hki34@uclive.ac.nz',
        keywords = 'security analysis framework',
        packages = find_packages(),
        install_requires=['networkx', 'tabulate'],
)
