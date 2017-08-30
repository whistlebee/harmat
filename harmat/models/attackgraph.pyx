import networkx
from collections import OrderedDict
import statistics
import harmat as hm
from libcpp.vector cimport vector
from libcpp.pair cimport pair
from libcpp.unordered_map cimport unordered_map
from libcpp.unordered_set cimport unordered_set
from libcpp.cast cimport static_cast
from cython.operator cimport dereference as deref
from cython.operator cimport preincrement as inc
from libc.stdint cimport uintptr_t, uint32_t
from ..graph cimport HarmatGraph, Node, NodeProperty, Nptr
from ..bglgraph cimport Graph
from ..extras cimport remove
from cython.parallel import parallel, prange
cimport cython


class HarmNotFullyDefinedError(Exception): pass


class NoAttackPathExists(Exception): pass


cdef class AttackGraph(HarmatGraph):
    """
    Attack Graph class.
    An Attack graph is a way to model the security of a network.
    This class inherits from networkx directed graph class so that we can use
    all of its functions which are relevant
    """

    cdef vector[vector[Nptr]] cy_all_paths
    cdef public Node source
    cdef public Node target
    cdef public object values

    def __cinit__(self):
        self.cy_all_paths = vector[vector[Nptr]]()
        self.source = None
        self.target = None
        self.values = OrderedDict()

    def __init__(self):
        super(AttackGraph, self).__init__()

    def __repr__(self):
        return self.__class__.__name__

    @cython.boundscheck(False)
    def find_paths(self):
        """
        Finds all paths between the source (Attacker) and all other nodes.
        This function is *very* expensive.
        If target is specified, it will find all paths between the attacker and the target node
        :param target: Specified target node
        """
        cdef vector[NodeProperty*] nodes
        if self.source is None:
            raise HarmNotFullyDefinedError('Source is not set')
        if self.target is None:
            nodes = deref(self.graph_ptr).nodes()
            # remove source node from nodes
            nodes.erase(remove(nodes.begin(), nodes.end(), self.source.np), nodes.end())
        else:
            nodes = vector[Nptr]()
            nodes.push_back(self.target.np)
        self.cy_all_paths = find_attack_paths(self, self.source.np, nodes)


    def flowup(self):
        for node in self.hosts():
            if node.lower_layer is not None:
                node.flowup()

    @property
    def impact(self):
        if self.all_paths is None:
            self.find_paths()
        return max(self.path_impact(path) for path in self.all_paths)

    @staticmethod
    def path_impact(path):
        return sum(node.impact for node in path[1:])

    @property
    def all_paths(self):
        cdef vector[vector[Nptr]].iterator path_it = self.cy_all_paths.begin()
        cdef vector[Nptr].iterator it
        paths = []
        while path_it != self.cy_all_paths.end():
            it = deref(path_it).begin()
            path = []
            while it != deref(path_it).end():
                path.append(deref(deref(it)))
                inc(it)
            paths.append(path)
            inc(path_it)
        return paths

    def check_attack_paths(self):
        if self.cy_all_paths.empty():
            self.find_paths()
            if self.cy_all_paths.empty():
                raise NoAttackPathExists()

    @cython.wraparound(False)
    @cython.boundscheck(False)
    @property
    def risk(self):
        """
        Calculate the risk of this AttackGraph

        The high level algorithm is as follows:
            1. Find all possible paths from one node to another. However, we
            ignore paths which contain loops.
            2. Find the max of the risk of all paths.
                i. To calculate the risk of a path, sum up the individual risk
                values of all nodes in that path.
        Args:
            source: the source node. Usually should be the Attacker
            target: the designated target node

        Returns:
            The total risk calculated.

        """
        self.check_attack_paths()
        cdef double cur_max
        cdef pathrisk
        cdef vector[vector[Nptr]].iterator path_it = self.cy_all_paths.begin()
        cur_max = self.path_risk(deref(path_it))
        inc(path_it)
        while path_it != self.cy_all_paths.end():
            pathrisk = self.path_risk(deref(path_it))
            if pathrisk > cur_max:
                cur_max = pathrisk
            inc(path_it)
        return cur_max

    @cython.wraparound(False)
    @cython.boundscheck(False)
    cdef path_risk(self, vector[NodeProperty*] path):
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
        cdef double path_risk_sum = 0
        cdef vector[NodeProperty*].iterator it = path.begin()
        inc(it)
        while it != path.end():
            path_risk_sum += deref(it).risk * deref(it).asset_value
            inc(it)
        return path_risk_sum

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
        self.check_attack_paths()
        cdef double cur_min
        cdef pathrisk
        cdef vector[vector[Nptr]].iterator path_it = self.cy_all_paths.begin()
        cur_min = self.path_risk(deref(path_it))
        inc(path_it)
        while path_it != self.cy_all_paths.end():
            pathrisk = self.path_risk(deref(path_it))
            if pathrisk < cur_min:
                cur_min = pathrisk
            inc(path_it)
        return cur_min

    @cython.wraparound(False)
    cdef path_cost(self, vector[NodeProperty*] path):
        """
        Calculate the cost of an attack for a single path

        Args:
            path : this is a list (or generator) containing a path =between two
            nodes

        Returns:
            The calculated cost value
        """
        cdef double path_cost_sum = 0
        cdef vector[NodeProperty*].iterator it = path.begin()
        inc(it)
        while it != path.end():
            path_cost_sum += deref(it).cost
            inc(it)
        return path_cost_sum

    def return_on_attack(self):
        """
        Calculate the return on an attack.
        The maximum value from all attack paths are selected.
        Args:
            source : Node object. The source node. Usually the attacker.

            target : Node object. The target node.
        Returns:
            Numeric
        """
        self.check_attack_paths()
        return max(self.path_return(path) for path in self.all_paths)

    @staticmethod
    def path_return(path):
        """
        probability, impact and cost attributes must be set for all nodes
        """
        path_return = 0
        for node in path[1:]:
            if node.cost == 0:
                raise Exception('Zero cost host is not permitted')
            path_return += node.risk / node.cost
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
        self.check_attack_paths()
        path_len_generator = (len(path) - 1 for path in self.all_paths)
        return statistics.mean(path_len_generator)

    def mode_path_length(self):
        """
        Calculate the Mode of Path Length Metric
        """
        self.check_attack_paths()
        return max(len(path) for path in self.all_paths) - 1

    def stdev_path_length(self):
        """
        Calculate the standard deviation of path length
        """
        self.check_attack_paths()
        path_len_generator = (len(path) - 1 for path in self.all_paths)
        try:
            return statistics.stdev(path_len_generator)
        except:
            return 0

    def shortest_path_length(self):
        shortest_path = networkx.shortest_path(self, self.source, self.target)
        return len(shortest_path) - 1

    def add_edge_between(self, node1, nodes, two_ways=False):
        """
        Add edges between a node (node1) and all other nodes in nodes

        Args:
            node1: Node object
            nodes: Either Node object or a iterable containing nodes
        """
        if isinstance(nodes, hm.Node):
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
        Calculates the necessary metrics for visualisation or calculation
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

    def number_of_attack_paths(self):
        if self.all_paths is None:
            raise Exception('Attack paths have not been calculated')
        return self.cy_all_paths.size()

    def normalised_mean_path_length(self):
        num_paths = self.number_of_attack_paths()
        if num_paths == 0:
            raise ZeroDivisionError('No attack paths')
        return self.mean_path_length() / num_paths

    def probability_attack_success(self):
        self.check_attack_paths()
        return max(self.path_probability(path[1:]) for path in self.all_paths)

    @staticmethod
    def path_probability(path):
        # return reduce(lambda x, y: x * y, (host.lower_layer.values['probability'] for host in path[1:]))
        p = 1
        for host in path[1:]:
            prob = host.probability
            if prob == 0:
                return 0
            p *= prob
        return p

    def all_vulns(self):
        """
        :return: A set of all (unique) vulnerabilities
        """
        return {vul for vul in (node.lower_layer.all_vulns() for node in self.nodes())}

    def hosts(self):
        return filter(lambda x: not isinstance(x, hm.Attacker), self.nodes())

    def num_vulnerable_hosts(self):
        return len(filter_ignorables(list(self.hosts())))


def filter_ignorables(path):
    return [node for node in path if node.ignorable is False]

cdef bint is_vulnerable(NodeProperty* np) nogil:
    cdef bint rt = False
    cdef double p = deref(np).probability
    if p != 0:
        rt = True
    return rt

@cython.wraparound(False)
@cython.boundscheck(False)
cdef vector[vector[Nptr]] find_attack_paths(AttackGraph G, NodeProperty* source, vector[Nptr] targets):
    cdef vector[vector[Nptr]] all_paths
    cdef vector[vector[Nptr]] new_paths
    cdef vector[vector[Nptr]].iterator paths_it
    cdef vector[NodeProperty*].iterator targets_it = targets.begin()
    while targets_it != targets.end():
        new_paths = all_simple_attack_paths(G, source, deref(targets_it))
        paths_it = new_paths.begin()
        while paths_it != new_paths.end():
            all_paths.push_back(deref(paths_it))
            inc(paths_it)
        inc(targets_it)
    return all_paths

import time

ctypedef vector[Nptr].iterator vit

@cython.wraparound(False)
@cython.boundscheck(False)
cdef vector[vector[Nptr]] all_simple_attack_paths(AttackGraph G, NodeProperty* source, NodeProperty* target) nogil:
    """
    Modified and cythonized version of NetworkX _all_simple_paths_graph
    Notably, this ignores hosts with no vulnerabilities and ignores ignorable set hosts.

    :param G: Attack graph
    :param source: source node
    :param target: target node
    :param cutoff:
    :return:
    """
    cdef Graph[NodeProperty] graph_ptr
    with gil:
        graph_ptr = deref(G.graph_ptr)
    cdef uint32_t num_nodes = graph_ptr.num_vertices()
    cdef vector[vector[Nptr]] paths
    cdef uint32_t cutoff = num_nodes - 1
    cdef vector[Nptr] visited
    cdef vector[pair[vit, vit]] stack
    cdef unordered_set[NodeProperty*] traversed
    cdef vector[NodeProperty*] new_path
    cdef NodeProperty* child
    cdef vit* children
    cdef vit* children_end
    cdef vector[Nptr] out_nodes = graph_ptr.out_nodes(source)
    cdef pair[vit, vit] ppair
    if num_nodes < 2:
        return paths
    visited.push_back(source)
    traversed.insert(source)
    ppair.first = out_nodes.begin()
    ppair.second = out_nodes.end()
    stack.push_back(ppair)
    while stack.empty() == False:
        children = &(stack.back().first)
        children_end = &(stack.back().second)
        child = deref(deref(children))
        if deref(children) == deref(children_end):
            stack.pop_back()
            visited.pop_back()
        elif traversed.size() < cutoff:
            inc(deref(children))
            if child == target:
                new_path = vector[Nptr](visited)
                new_path.push_back(target)
                paths.push_back(new_path)
            elif traversed.find(child) == traversed.end() and (child.ignorable == True or is_vulnerable(child)):
                visited.push_back(child)
                traversed.insert(child)
                out_nodes = graph_ptr.out_nodes(child)
                ppair.first = out_nodes.begin()
                ppair.second = out_nodes.end()
                stack.push_back(ppair)
        else:
            if child == target or traversed.find(child) == traversed.end():
                new_path = vector[Nptr](visited)
                new_path.push_back(target)
                paths.push_back(new_path)
            stack.pop_back()
            visited.pop_back()
    return paths