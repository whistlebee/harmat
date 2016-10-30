"""
Attack Tree class
Author: hki34
"""
import networkx
from .node import *

class AttackTree(networkx.DiGraph):
    """
    Attack Tree class
    Must specify the rootnode variable before use
    """
    def __init__(self, root=None):
        networkx.DiGraph.__init__(self)
        self.rootnode = root

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
            children_nodes = self[current_node]
            values = list(map(self.flowup, children_nodes))
            if current_node.gatetype == 'or':
                current_node.values['risk'] = max(value_dict['risk'] for value_dict in values)
                current_node.values['cost'] = min(value_dict['cost'] for value_dict in values)
                current_node.values['impact'] = max(value_dict['impact'] for value_dict in values)
                current_node.values['probability'] = max(value_dict['probability'] for value_dict in values)
            elif current_node.gatetype == 'and':
                current_node.values['risk'] = sum(value_dict['risk'] for value_dict in values)
                current_node.values['cost'] = sum(value_dict['cost'] for value_dict in values)
                current_node.values['impact'] = sum(value_dict['impact'] for value_dict in values)
                #Write metric calculation for probability in and gate
            return current_node.values
        else:
            raise TypeError("Weird type came in: {}".format(type(current_node)))



    def all_vulns(self):
        """
        Returns all Vulnerability objects in this Attack Tree

        Returns:
            A list containing all vulnerabilities
        """
        return [vul for vul in self.nodes() if isinstance(vul, Vulnerability)]

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
        Add a vulnerability to a logic gate
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
            vulns:  A list containing vulnerabilities
        """
        lg = LogicGate("or")
        self.rootnode = lg
        self.add_node(lg)
        if not isinstance(vulns, list):
            vulns = [vulns]
        for vuln in vulns:
            self.at_add_node(vuln, lg)

