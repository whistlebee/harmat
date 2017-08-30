import pyximport; pyximport.install()
from .node import LogicGate, Vulnerability, RootNode
from collections import OrderedDict
from functools import reduce
from ..graph import DuplicableHarmatGraph


# Some helper functions for ignoring None values
# Useful when Harm is not fully defined

def ignore_none_func(func, iterable):
    return func(filter(lambda x: x is not None, iterable))

def flowup_sum(iterable):
    return ignore_none_func(sum, iterable)


def flowup_max(iterable):
    return ignore_none_func(max, iterable)


def flowup_min(iterable):
    return ignore_none_func(min, iterable)


def flowup_or_prob(iterable):
    return 1 - reduce(lambda x, y: x * y, map(lambda x: 1 - x, iterable))


def flowup_and_prob(iterable):
    return reduce(lambda x, y: x * y, iterable)


class AttackTree(DuplicableHarmatGraph):
    """
    Attack Tree class
    Must specify the rootnode variable before use
    """

    # Change this dictionary to have a custom calculation method
    # Try to use OrderedDict so that the calculation order is deterministic
    flowup_calc_dict = OrderedDict({
        'or': OrderedDict({
            'risk': flowup_max,
            'cost': flowup_min,
            'impact': flowup_max,
            'probability': flowup_or_prob
        }),
        'and': OrderedDict({
            'risk': flowup_sum,
            'cost': flowup_sum,
            'impact': flowup_sum,
            'probability': flowup_and_prob
        }),
    })

    def __init__(self, host=None):
        super(AttackTree, self).__init__()
        if host is not None:
            rootnode = RootNode('or', host)
        else:
            rootnode = LogicGate('or')
        self.add_node(rootnode)
        self.rootnode = rootnode

    def add_node(self, node):
        super(AttackTree, self).add_node(node)

    def __repr__(self):
        return self.__class__.__name__

    @property
    def values(self):
        return self.rootnode.values

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
            values = [self.flowup(child) for child in children_nodes if child is not None]
            if values:
                for metric, function in self.flowup_calc_dict[current_node.gatetype].items():
                    setattr(current_node, metric, function(value_dict.get(metric) for value_dict in values))
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

    def patch_subtree(self, node):
        for child in self[node]:
            self.patch_subtree(child)
        self.remove_node(node)

    # FIXME: implement self.parent()
    def patch_vul(self, vul, is_name=False):
        if is_name:
            vul = self.find_vul_by_name(vul)
        if vul in self.nodes():
            if self.parent(vul).gatetype == 'and':  # delete whole predecessor tree if it is an AND gate
                self.patch_subtree(self.parent(vul))
            else:
                self.patch_subtree(vul)

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
        lg = self.rootnode
        if not isinstance(vulns, list):
            vulns = [vulns]
        for vuln in vulns:
            self.at_add_node(vuln, lg)
