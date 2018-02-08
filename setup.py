from codecs import open
import os
import sys
from sys import platform
from setuptools import find_packages, Extension, setup

if sys.version_info <= (3, 4):
    sys.exit('Only Python 3.4 and up are supported')

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

requirement_files = ['requirements.txt']
req = []
for req_filename in requirement_files:
    with open(req_filename, 'r') as reqfile:
        req.extend(reqfile.read().splitlines())

'''
Cython stuff
'''

try:
    from Cython.Distutils import build_ext
    from Cython.Build import cythonize
except ImportError:
    raise Exception('Cython is not installed!')


def make_extension(extension_name):
    extPath = extension_name.replace('.', os.path.sep) + '.pyx'
    return Extension(
        extension_name,
        [extPath],
        include_dirs=include_dirs,  # adding the '.' to include_dirs is CRUCIAL!!
        extra_compile_args=extra_compile_args,
        language='c++'
    )


def scandir(dir, files=None):
    if files is None:
        files = []
    for file in os.listdir(dir):
        path = os.path.join(dir, file)
        if os.path.isfile(path) and path.endswith('.pyx'):
            files.append(path.replace(os.path.sep, '.')[:-4])
        elif os.path.isdir(path):
            scandir(path, files)
    return files


GRAPH_SOURCE_DIR = 'harmat/graph/'

include_dirs = ['.', 'harmat']
extra_compile_args = []
extra_link_args = []

if platform == 'linux' or platform == 'linux2':
    # Linux
    lin_extra_compile_args = ['-std=c++14']
    lin_extra_link_args = []
    extra_compile_args.extend(lin_extra_compile_args)
    extra_link_args.extend(lin_extra_link_args)
elif platform == 'darwin':
    # macOS
    mac_extra_compile_args = ['-std=c++14', '-Wdeprecated', '-Wno-unreachable-code', '-mmacosx-version-min=10.9',
                              '-Wdeprecated']
    mac_extra_link_args = []
    extra_compile_args.extend(mac_extra_compile_args)
    extra_link_args.extend(mac_extra_link_args)
elif platform == 'win32':
    # Windows
    win_include_dirs = ['C:\\Libraries\\boost_1_65_1']
    include_dirs.extend(win_include_dirs)
    win_extra_compile_args = ['/std:c++14']
    win_extra_link_args = []
    extra_compile_args.extend(win_extra_compile_args)
    extra_link_args.extend(win_extra_link_args)

# get the list of extensions
extension_names = scandir('harmat')

# and build up the set of Extension objects
extensions = [make_extension(name) for name in extension_names]

# finally, we can pass all this to distutils
setup(
    name='harmat',
    version='2.0',
    author='Hyunjin Kim',
    author_email='hki34@uclive.ac.nz',
    packages=find_packages() + ['harmat.models'],
    install_requires=req,
    ext_modules=extensions,
    cmdclass={'build_ext': build_ext}
)
