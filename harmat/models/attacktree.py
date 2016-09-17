"""
Attack Tree class
Author: hki34
"""
import networkx
from node import *

class AttackTree(networkx.DiGraph):
    """
    Attack Tree class

    Must specify the rootnode variable before use
    """
    def __init__(self, root=None):
        networkx.DiGraph.__init__(self)
        self.rootnode = root
        self.risk = None

    def all_vulns(self):
        """
        Returns all Vulnerability objects in this Attack Tree

        Returns:
            A list containing all vulnerabilities
        """
        vuls_list = []
        for node in self.nodes():
            if isinstance(node, Vulnerability):
                vuls_list.append(node)
        return vuls_list

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
                if type(node) != LogicGate and node.vulname == name:
                    object_list.append(node)

        self.remove_nodes_from(object_list)

    def traverse(self, root=None):
        if root is None:
            root = self.rootnode
        children_nodes = self[root]
        for node in children_nodes:
            self.traverse(node)
            yield node

    def calculate_risk(self, current_node=None, validation=False, alt_risk_metric=None):
        """
        Calculate the risk of the Attack Tree. We do this recursively.
        To calculate the risk value for logic gate nodes, we consider if the
        node is either a AND gate or OR gate.
        In the case of the AND gate, the risk value is the sum of its children.
        For the OR gate, the risk value is the highest risk value of its
        children.
        Args:
            current_node: the node we are processing

            validation: Sometimes the Attack Tree may not have specified all
            the risk metrics necessary for this calculation. By setting this
            variable as True, we check the AttackTree that all vulnerabilities
            have risk values. If some values are not specified, we throw an
            exception. Else, we ignore the value.

            alt_risk_metric: To specify a different attribute other than
            'self.risk', set this value to any of the following:
                'cvss'
        Returns:
            The risk calcuated for this tree
        This method stores the calculated final risk value as the tree's risk
        attribute.
        """
        if current_node == None:
            current_node = self.rootnode

        if isinstance(current_node, Vulnerability):
            #check for validation and alternate risk metrics
            if alt_risk_metric:
                if alt_risk_metric == 'cvss':
                    metric = current_node.cvss
            else:
                metric = current_node.risk

            if validation:
                if metric == None:
                    raise Exception('Risk Metric not specified for this node!')

            return metric

        risk = 0
        if isinstance(current_node, LogicGate):
            #children_nodes is a set containing all connected nodes with
            #current_node
            try:
                children_nodes = self[current_node]
                if current_node.gatetype == 'and':
                    for child in children_nodes:
                        risk += self.calculate_risk(child)
                elif current_node.gatetype == 'or':
                    #set the max risk value as the risk for this node
                    for child in children_nodes:
                        calculated_risk = self.calculate_risk(child,validation=validation,alt_risk_metric=alt_risk_metric)
                        if calculated_risk > risk:
                            risk = calculated_risk
                current_node.risk = risk
            except KeyError:
                pass
        else:
            #Some other class came in
            print(current_node)
            raise Exception('Some other class detected')

        #Check if it is the root node and add the attribute
        if current_node == self.rootnode:
            self.risk = risk
        return risk

    def add_vuln(self, vuln, logic_gate=None):
        """
        Add a vulnerability to a logic gate
        """

        if logic_gate is None:
            logic_gate = self.rootnode
        self.add_node(vuln)
        self.add_edge(logic_gate, vuln)

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
        if type(vulns) is not list:
            vulns = [vulns]
        for vuln in vulns:
            self.add_vuln(vuln, lg)

