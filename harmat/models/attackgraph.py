"""
Attack Graph class implementation
author: hki34
"""
import networkx
from .node import *
class AttackGraph(networkx.DiGraph):
    """
    Attack Graph class.
    An Attack graph is a way to model the security of a network.
    This class inherits from networkx directed graph class so that we can use
    all of its functions which are relevant
    """
    def __init__(self):
        networkx.DiGraph.__init__(self)

    def calculate_risk(self, source, target):
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
        paths = networkx.all_simple_paths(self, source, target)
        total_risk = 0
        for path in paths:
            total_risk += self.calculate_path_risk(path)
        return total_risk

    def calculate_highest_risk_path(self, source, target):
        paths = networkx.all_simple_paths(self, source, target)
        maximum = None
        for path in paths:
            path_risk = self.calculate_path_risk(path)
            if maximum is None or path_risk > maximum:
                maximum = path_risk
        return maximum

    def calculate_path_risk(self, path):
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
        risk_total = 0
        for node in path:
            try:
                risk_total += node.risk
            except:
                #if risk value is not defined
                try:
                    node.lower_layer.calculate_risk()
                    risk_total += node.lower_layer.risk
                except:
                    #case when no lower layer
                    pass
                #raise Exception("Risk value not defined on node")
        return risk_total

    def calculate_cost(self, source, target):
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
        minimum_cost = None
        paths = networkx.all_simple_paths(self, source, target)
        for path in paths:
            path_cost = self.calculate_path_cost(path)
            if minimum_cost is None or path_cost < minimum_cost:
                minimum_cost = path_cost
        return minimum_cost

    def calculate_path_cost(self, path):
        """
        Calculate the cost of an attack for a single path

        Args:
            path : this is a list (or generator) containing a path =between two
            nodes

        Returns:
            The calculated cost value
        """
        cost_total = 0
        for node in path:
            try:
                cost_total += node.cost
            except:
                raise Exception("Cost value not defined on node try running calculate_cost on the AT")
        return cost_total

    def calculate_return_on_attack(self, source, target):
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
        max_return = None
        paths = networkx.all_simple_paths(self, source, target)
        for path in paths:
            path_return = self.calculate_path_return(path)
            if max_return is None or path_return > max_return:
                max_return = path_return
        return max_return

    def calculate_path_return(self, path):
        """
        probability, impact and cost attributes must be set for all nodes
        """
        path_return = 0
        for node in path:
            try:
                path_return = (node.probability * node.impact) / node.cost
            except AttributeError:
                path_return = node.risk / node.cost
        return path_return

    def calculate_MPL(self, source, target):
        """
        Calculate the Mean of Path Metric
        Args:
            source:
            target:
        Returns:
            Numerical
        """
        path_sum = 0
        path_count = 0
        paths = networkx.all_simple_paths(self, source, target)
        for path in paths:
            path_sum += len(path) - 1
            if len(path) != 0:
                path_count += 1
        if path_count == 0:
            return 0
        mpl = path_sum / path_count
        return mpl

    def calculate_MoPL(self, source, target):
        """
        Calculate the Mode of Path Length Metric
        """
        highest = None
        paths = networkx.all_simple_paths(self, source, target)
        for path in paths:
            if highest is None or len(path)-1 > highest:
                highest = len(path)-1
        return highest

    def calculate_SDPL(self, source, target):
        """
        Calculate the Standard Deviation of Path length
        :param source:
        :param target:
        :return:
        """
        mean = self.calculate_MPL(source, target)
        paths = networkx.all_simple_paths(self, source, target)
        squared_differences = []
        for path in paths:
            squared_differences.append( ((len(path)-1) - mean) ** 2 )
        if len(squared_differences) == 0:
            return 0
        return sum(squared_differences)/len(squared_differences)

    def calculate_shortest_path_length(self, source, target):
        shortest_path = networkx.shortest_path(self, source, target)
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

    def betweenness_centrality(self):
        """
        Calculates the betweenness centrality
        Returns:
             A dictionary of nodes with values assigned to them
        """
        return networkx.betweenness_centrality(self)

    def closeness_centrality(self):
        return networkx.closeness_centrality(self)

    def degree_centrality(self):
        return networkx.degree_centrality(self)

    def initialise_vis_metrics(self):
        """
        Calculates the necessary metrics for visualisation
        Currently:
        Risk (top layer and lower layer), Centrality
        :return:
        """
        #initialise centrality measure
        betweenness = self.degree_centrality()
        closeness = self.closeness_centrality()
        degree = self.degree_centrality()


        #initialise host nodes risk metrics and give value for centrality
        for node in self.nodes():
            if not isinstance(node, Host):
                raise TypeError("Non Host node in AG")
            node.lower_layer.calculate_risk()
            node.centrality = (betweenness[node] + closeness[node] + degree[node])/3
