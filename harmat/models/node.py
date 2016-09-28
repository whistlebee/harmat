"""
Node class
Author: hki34
"""
class Node(object):
    """
    This class defines a Node object which describes any type of node which is used
    in HARM. It may be a host, vulnerability or anything else. It is used in any
    type of any graph model such as: Attack Graph, Attack Tree and HARM.

    Args:
        type: refers to the type of node it is

    e.g. "vulnerability" would mean it is a vulnerability node
    """
    def __init__(self, type_, **kwargs):
        self.type = type_
        self.values = {}


    @property
    def risk(self):
        return self.values['risk']

    @property
    def cost(self):
        return self.values['cost']

    @property
    def impact(self):
        return self.values['impact']

    @property
    def probability(self):
        return self.values['probability']


class Vulnerability(Node):
    def __init__(self, name, values={}):
        Node.__init__(self, "vulnerability")
        self.name = name
        self.values = values

    def __repr__(self):
        return "{}-{}".format(self.__class__.__name__, self.name)


class LogicGate(Node):
    def __init__(self, gatetype):
        Node.__init__(self, "logicgate")
        self.gatetype = gatetype

    def validate_gatetype(self, gt):
        """
        Check that the gatetype string is a valid one

        Args:
            gt: The string to input check
        Returns:
            Boolean.
        """
        valid_strings = ["or", "and"]
        if gt not in valid_strings:
            return False
        return True

    def __repr__(self):
        return "{}:{}".format(self.__class__.__name__, self.gatetype)


class Host(Node):
    def __init__(self, name, values={}):
        Node.__init__(self, "host")
        self.name = name
        self.lower_layer = None
        self.values = values

    def flowup(self):
        self.lower_layer.flowup()
        self.values = self.lower_layer.rootnode.values

    def __repr__(self):
        return "{}:{}".format(self.__class__.__name__, self.name)
