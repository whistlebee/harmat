#setup file

from codecs import open
from os import path

from setuptools import setup, find_packages

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()


setup(
        name = 'sample',
        version = '0.1',
        description = 'HARMAT project',
        url='https://github.com/whistlebee/harmat',
        author = 'Paul Kim',
        author_email = 'hki34@uclive.ac.nz',
        license = 'MIT',
        keywords = 'security analysis framework',
        packages = find_packages(),
        install_requires=['networkx', 'tabulate']
)
