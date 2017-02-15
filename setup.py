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
        install_requires=['networkx', 'tabulate', 'lxml'],
)
