"""
Attack Tree class
Author: hki34
"""
import networkx
from .node import *
from collections import OrderedDict

class AttackTree(networkx.DiGraph):
    """
    Attack Tree class
    Must specify the rootnode variable before use
    """
    def __init__(self, root=None):
        networkx.DiGraph.__init__(self)
        self.rootnode = root

        # Change this dictionary to have a custom calculation method
        # Try to use OrderedDict so that the calculation order is deterministic
        self.flowup_calc_dict = OrderedDict({
            'or': OrderedDict({
                'risk': max,
                'cost': min,
                'impact': max,
                'probability': max
            }),
            'and': OrderedDict({
                'risk': sum,
                'cost': sum,
                'impact': sum
            })
        })

    def __repr__(self):
        return self.__class__.__name__

    @property
    def values(self):
        return self.rootnode.values

    @property
    def is_vulnerable(self):
        for node in self.nodes():
            if isinstance(node, Vulnerability):
                return True
        return False


    def flowup(self, current_node=None):
        if current_node is None:
            current_node = self.rootnode
        if isinstance(current_node, Vulnerability):
            return current_node.values
        elif isinstance(current_node, LogicGate):
            children_nodes = self.neighbors(current_node)
            values = list(map(self.flowup, children_nodes))
            for metric, function in self.flowup_calc_dict[current_node.gatetype].items():
                current_node.values[metric] = function(value_dict[metric] for value_dict in values)
            return current_node.values
        else:
            raise TypeError("Weird type came in: {}".format(type(current_node)))


    def all_vulns(self):
        """
        Returns all Vulnerability objects in this Attack Tree

        Returns:
            A generator containing all vulnerabilities
        """
        return (vul for vul in self.nodes() if isinstance(vul, Vulnerability))

    def patch_vulns(self, names_list):
        """
        Patch given vulnerabilities from this attack tree.

        Args:
            names_list: a iterable (list, dict...) containing the names of the vulnerabilities to patch
        """
        #convert the names to the references to the Node objects
        object_list = []
        for name in names_list:
            for node in self.nodes():
                if type(node) != LogicGate and node.name == name:
                    object_list.append(node)

        self.remove_nodes_from(object_list)

    def at_add_node(self, node, logic_gate=None):
        """
        Add a vulnerability to a logic gate.
        If logic_gate is not specified, this will default to adding to the rootnode
        """
        if logic_gate is None:
            logic_gate = self.rootnode
        self.add_node(node)
        self.add_edge(logic_gate, node)

    def basic_at(self, vulns):
        """
        Creates a basic Attack tree which contains vulnerabilities in vulns like the following:

                root
                 |
                 OR
            -------------
            | | | | | | |
            v v v v v v v

        Args:
            vulns:  A list containing vulnerabilities/logic gate. Can be a single node.
        """
        if self.rootnode is None: #if rootnode hasn't been created yet
            lg = LogicGate("or")
            self.rootnode = lg
            self.add_node(lg)
        else:
            lg = self.rootnode #if rootnode already exists, just add nodes to that
        if not isinstance(vulns, list):
            vulns = [vulns]
        for vuln in vulns:
            self.at_add_node(vuln, lg)
