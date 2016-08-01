"""
Node class
Author: hki34
"""
import networkx

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

class Vulnerability(Node):
    def __init__(self, vulname, risk=None):
        Node.__init__(self, "vulnerability")
        self.vulname = vulname
        self.cvss = None
        self.risk = risk

    def __repr__(self):
        return "{}-{}".format(self.vulname, self.risk)

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
        return self.gatetype

class Host(Node):
    def __init__(self, name=None):
        Node.__init__(self, "host")
        self.name = name
        self.risk = None
        self.lower_layer = None

    def calculate_risk(self):
        return self.lower_layer.calculate_risk()

    def __repr__(self):
        return self.name
