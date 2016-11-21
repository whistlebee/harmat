"""
Attack Graph class implementation
author: hki34
"""
import networkx
import warnings
import statistics


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
        self.all_paths = None

    def __repr__(self):
        return self.__class__.__name__

    def find_paths(self):
        self.all_paths = list(_all_simple_paths_graph(self, self.source, self.target))

    def flowup(self):
        for node in self.nodes():
            node.flowup()

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
        if self.all_paths is None:
            self.find_paths()
        return max(self.path_risk(path) for path in self.all_paths)

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
        return sum(node.values['risk'] for node in path[1:])

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
        if not self.all_paths:
            self.find_paths()
        return min(self.path_cost(path) for path in self.all_paths)

    def path_cost(self, path):
        """
        Calculate the cost of an attack for a single path

        Args:
            path : this is a list (or generator) containing a path =between two
            nodes

        Returns:
            The calculated cost value
        """
        return sum(node.values['cost'] for node in path[1:])

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
        if self.all_paths is None:
            self.find_paths()
        return max(self.path_return(path) for path in self.all_paths)

    def path_return(self, path):
        """
        probability, impact and cost attributes must be set for all nodes
        """
        path_return = None
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
        if self.all_paths is None:
            self.find_paths()
        path_len_generator = (len(path)-1 for path in self.all_paths)
        return statistics.mean(path_len_generator)

    def mode_path_length(self):
        """
        Calculate the Mode of Path Length Metric
        """
        if self.source is None or self.target is None:
            raise HarmNotFullyDefinedError("Source or Target may not be defined")
        if self.all_paths is None:
            self.find_paths()
        return max(len(path) for path in self.all_paths) - 1

    def stdev_path_length(self):
        """
        Calculate the standard deviation of path length
        """
        if self.source is None or self.target is None:
            raise HarmNotFullyDefinedError("Source or Target may not be defined")
        if self.all_paths is None:
            self.find_paths()
        path_len_generator = (len(path)-1 for path in self.all_paths)
        return statistics.stdev(path_len_generator)

    def shortest_path_length(self):
        if self.source is None or self.target is None:
            raise HarmNotFullyDefinedError("Source or Target may not be defined")

        shortest_path = networkx.shortest_path(self, self.source, self.target)
        return len(shortest_path) - 1

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
            node.centrality = (betweenness[node] + closeness[node] + degree[node]) / 3


def _all_simple_paths_graph(G, source, target, cutoff=None):
    """
    Modified version of NetworkX _all_simple_paths_graph
    but for attack graphs.
    Notably, this ignores hosts with no vulnerabilities.

    :param G:
    :param source:
    :param target:
    :param cutoff:
    :return:
    """

    if cutoff is None:
        cutoff = len(G)-1

    if cutoff < 1:
        return
    visited = [source]
    stack = [iter(G[source])]
    while stack:
        children = stack[-1]
        child = next(children, None)
        if child is None:
            stack.pop()
            visited.pop()
        elif len(visited) < cutoff:
            if child == target:
                yield visited + [target]
            elif child not in visited and child.lower_layer.is_vulnerable:
                #must check that there are vulnerabilities
                visited.append(child)
                stack.append(iter(G[child]))
        else: #len(visited) == cutoff:
            if child == target or target in children:
                yield visited + [target]
            stack.pop()
            visited.pop()
