from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from future import standard_library

standard_library.install_aliases()
from .xml_parser import parse_xml, convert_to_xml, write_to_file, convert_to_safeview
from .tiscovery_parser import tiscovery_parser
