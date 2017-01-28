"""
Node class
Author: hki34
"""

#Use to define valid gatetypes for logic gates
VALID_GATES = ['or', 'and']


class Node(object):
    """
    This class defines a Node object which describes any type of node which is used
    in HARM. It may be a host, vulnerability or anything else. It is used in any
    type of any graph model such as: Attack Graph, Attack Tree and HARM.
    """
    def __init__(self):
        #super(Node, self).__setattr__('values', dict())
        self.__dict__['values'] = dict()


    def __getattr__(self, item):
        if 'values' not in self.__dict__: #Fix issues with deepcopy
            self.__dict__['values'] = dict()
        if item in self.values:
            return self.values[item]
        else:
            raise AttributeError()


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

    def flowup(self):
        self.lower_layer.flowup()
        self.values.update(self.lower_layer.rootnode.values)


    def __repr__(self):
        return '{}:{}'.format(self.__class__.__name__, self.name)
