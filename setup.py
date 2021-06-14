import os
import sys
import glob
from codecs import open
from setuptools import find_packages, Extension, setup
from Cython.Distutils import build_ext
from Cython.Build import cythonize

if sys.version_info <= (3, 4):
    sys.exit('Only Python 3.4 and up are supported')

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

include_dirs = ['.', 'harmat']

if sys.platform == 'linux' or sys.platform == 'linux2':
    extra_compile_args = ['-std=c++14']
elif sys.platform == 'darwin':
    extra_compile_args = ['-std=c++14', '-Wdeprecated', '-Wno-unreachable-code',
                          '-mmacosx-version-min=10.9', '-Wall']
elif sys.platform == 'win32':
    extra_compile_args = ['/std:c++14']


def make_extension(path):
    modulename, ext = os.path.splitext(path)
    modulename = modulename.replace(os.path.sep, '.')

    return Extension(
        name=modulename,
        sources=[path],
        include_dirs=include_dirs,
        extra_compile_args=extra_compile_args
    )
extensions = [make_extension(path) for path in glob.iglob('harmat/**/*.pyx', recursive=True)]
setup(
    name='harmat',
    version='2.0',
    author='Hyunjin Kim',
    packages=find_packages() + ['harmat.models'],
    ext_modules=cythonize(extensions),
    cmdclass={'build_ext': build_ext}
)
