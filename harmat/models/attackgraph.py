"""
Attack Graph class implementation
author: hki34
"""
import networkx
import warnings
from .node import *


class HarmNotFullyDefinedError(Exception): pass
class NoAttackPathExists(Exception): pass

class AttackGraph(networkx.DiGraph):
    """
    Attack Graph class.
    An Attack graph is a way to model the security of a network.
    This class inherits from networkx directed graph class so that we can use
    all of its functions which are relevant
    """

    def __init__(self):
        networkx.DiGraph.__init__(self)
        self.source, self.target = None, None

    @property
    def risk(self):
        """
        Calculate the risk of this AttackGraph

        The high level algorithm is as follows:
            1. Find all possible paths from one node to another. However, we
            ignore paths which contain loops.
            2. Sum up the risk of all paths.
                i. To calculate the risk of a path, sum up the individual risk
                values of all nodes in that path.
        Args:
            source: the source node. Usually should be the Attacker
            target: the designated target node

        Returns:
            The total risk calculated.

        """
        if self.source is None or self.target is None:
            raise HarmNotFullyDefinedError("Source or Target may not be defined")
        paths = networkx.all_simple_paths(self, self.source, self.target)
        return sum([self.path_risk(path) for path in paths])

    def calculate_highest_risk_path(self, source, target):
        if self.source is None or self.target is None:
            raise HarmNotFullyDefinedError("Source or Target may not be defined")
        paths = networkx.all_simple_paths(self, self.source, self.target)
        return max([self.path_risk(path) for path in paths])

    def path_risk(self, path):
        """
        Calculate the risk of a path

        Args:
            path: this is a list (or generator) containing a path between two nodes
            E.g.
            [0, 2, 1, 3]
            where 0..3 are the nodes in the path.
        Returns:
            The risk value calculated

        """
        return sum([node.values['risk'] for node in path])

    @property
    def cost(self):
        """
        Calculate the cost of this Attack Grpah

        This is is minimum value of the path cost values of all attack paths
        between a source node and target node

        Args:
            source: the originating node. Usually the attacker.

            target: targetted node.
        Returns:
            The cost of an attack
        """
        if self.source is None or self.target is None:
            raise HarmNotFullyDefinedError("Source or Target may not be defined")
        paths = networkx.all_simple_paths(self, self.source, self.target)
        return min(self.path_cost(path) for path in paths)

    def path_cost(self, path):
        """
        Calculate the cost of an attack for a single path

        Args:
            path : this is a list (or generator) containing a path =between two
            nodes

        Returns:
            The calculated cost value
        """
        return sum(node.values['cost'] for node in path)

    def return_on_attack(self):
        """
        Calculate the return on an attack.
        It is calculated by:
        Return = (Probabiliy * Impact) / Cost
        The maximum value from all attack paths are selected.
        Args:
            source : Node object. The source node. Usually the attacker.

            target : Node object. The target node.
        Returns:
            Numeric
        """
        if self.source is None or self.target is None:
            raise HarmNotFullyDefinedError("Source or Target may not be defined")
        paths = networkx.all_simple_paths(self, self.source, self.target)
        return max([self.path_return(path) for path in paths])

    def path_return(self, path):
        """
        probability, impact and cost attributes must be set for all nodes
        """
        path_return = 0
        for node in path:
            try:
                path_return = (node.values['probability'] * node.values['impact']) / node.values['cost']
            except KeyError:
                warnings.warn("Probability/Impact not defined. Using risk instead")
                path_return = node.values['risk'] / node.values['cost']
        return path_return

    def mean_path_length(self):
        """
        Calculate the Mean of Path Metric
        Args:
            source:
            target:
        Returns:
            Numerical
        """
        if self.source is None or self.target is None:
            raise HarmNotFullyDefinedError("Source or Target may not be defined")
        path_sum = 0
        path_count = 0
        paths = networkx.all_simple_paths(self, self.source, self.target)
        for path in paths:
            path_sum += len(path) - 1
            if len(path) != 0:
                path_count += 1
        if path_count == 0:
            return 0
        mpl = path_sum / path_count
        return mpl

    def mode_path_length(self):
        """
        Calculate the Mode of Path Length Metric
        """
        if self.source is None or self.target is None:
            raise HarmNotFullyDefinedError("Source or Target may not be defined")
        paths = networkx.all_simple_paths(self, self.source, self.target)
        return max([len(path) for path in paths]) - 1

    def standard_deviation_path_length(self):
        """
        Calculate the Standard Deviation of Path length
        :param source:
        :param target:
        :return:
        """
        if self.source is None or self.target is None:
            raise HarmNotFullyDefinedError("Source or Target may not be defined")
        mean = self.mean_path_length()
        paths = networkx.all_simple_paths(self, self.source, self.target)
        squared_differences = []
        for path in paths:
            squared_differences.append(((len(path) - 1) - mean) ** 2)
        if len(squared_differences) == 0:
            return 0
        return sum(squared_differences) / len(squared_differences)

    def shortest_path_length(self):
        if self.source is None or self.target is None:
            raise HarmNotFullyDefinedError("Source or Target may not be defined")

        shortest_path = networkx.shortest_path(self, self.source, self.target)
        return len(shortest_path)

    def add_edge_between(self, node1, nodes, two_ways=False):
        """
        Add edges between a node (node1) and all other nodes in nodes

        Args:
            node1: Node object
            nodes: Either Node object or a iterable containing nodes
        """
        if type(nodes) is not list:
            nodes = [nodes]

        for node in nodes:
            self.add_edge(node1, node)

        if two_ways is True:
            for node in nodes:
                self.add_edge(node, node1)

    def find_node(self, node_name):
        """
        Returns the object with the same name as node_name

        Args:
            node_name: String
        Returns:
            Node object
            or
            None: if no node with node_name is found
        """
        for node in self.nodes():
            if node.name == node_name:
                return node
        return None

    @property
    def betweenness_centrality(self):
        """
        Calculates the betweenness centrality
        Returns:
             A dictionary of nodes with values assigned to them
        """
        return networkx.betweenness_centrality(self)

    @property
    def closeness_centrality(self):
        return networkx.closeness_centrality(self)

    @property
    def degree_centrality(self):
        return networkx.degree_centrality(self)

    def initialise_centrality_measure(self):
        """
        Calculates the necessary metrics for visualisation
        Currently:
        Risk (top layer and lower layer), Centrality
        :return:
        """
        # initialise centrality measure
        betweenness = self.betweenness_centrality
        closeness = self.closeness_centrality
        degree = self.degree_centrality

        # initialise host nodes risk metrics and give value for centrality
        for node in self.nodes():
            if not isinstance(node, Host):
                raise TypeError("Non Host node in AG")
            node.centrality = (betweenness[node] + closeness[node] + degree[node]) / 3
