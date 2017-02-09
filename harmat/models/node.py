"""
Node class
Author: hki34
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from builtins import dict

from future import standard_library

standard_library.install_aliases()
VALID_GATES = ['or', 'and']


class Node(object):
    """
    This class defines a Node object which describes any type of node which is used
    in HARM. It may be a host, vulnerability or anything else. It is used in any
    type of any graph model such as: Attack Graph, Attack Tree and HARM.
    """

    def __init__(self):
        # super(Node, self).__setattr__('values', dict())
        self.__dict__['values'] = dict()

    def __getattr__(self, item):
        if 'values' not in self.__dict__:  # Fix issues with deepcopy
            self.__dict__['values'] = dict()
        if item in self.__dict__['values']:
            return self.__dict__['values'][item]
        if type(self) == Host and item not in ['__deepcopy__', '__getstate__', '__setstate__']: # fix deep copy stuff
            if item in self.__dict__['lower_layer'].rootnode.values:
                return self.__dict__['lower_layer'].rootnode.values[item]
        return self.__getattribute__(item)

    def __setattr__(self, key, value):
        if key in ['name', 'gatetype', 'lower_layer']:
            self.__dict__[key] = value
        elif key == 'values':
            self.values.update(value)
        elif key == 'meta':
            self.meta.update(value)
        else:
            self.values[key] = value


class Vulnerability(Node):
    def __init__(self, name, values=None):
        Node.__init__(self)
        self.name = name
        if values is not None:
            self.values.update(values)

    def __repr__(self):
        return '{}:{}'.format(self.__class__.__name__, self.name)


class LogicGate(Node):
    def __init__(self, gatetype):
        Node.__init__(self)
        self.gatetype = gatetype

    def validate_gatetype(self, gt):
        """
        Check that the gatetype string is a valid one

        Args:
            gt: The string to input check
        Returns:
            Boolean.
        """
        if gt not in VALID_GATES:
            return False
        return True

    def __repr__(self):
        return '{}:{}'.format(self.__class__.__name__, self.gatetype)


class Host(Node):
    def __init__(self, name, values=None):
        Node.__init__(self)
        self.__dict__['meta'] = dict()
        self.name = name
        self.lower_layer = None
        if values is not None:
            self.values.update(values)

    @property
    def values(self):
        return self.lower_layer.rootnode.values

    def flowup(self):
        self.lower_layer.flowup()

    def __repr__(self):
        return '{}:{}'.format(self.__class__.__name__, self.name)
