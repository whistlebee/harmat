import networkx
from collections import OrderedDict
import statistics
import harmat as hm
from libcpp.vector cimport vector
from libcpp.pair cimport pair
from libcpp.unordered_map cimport unordered_map
from libcpp.unordered_set cimport unordered_set
from libcpp.cast cimport static_cast
from libcpp.memory cimport unique_ptr
from cython.operator cimport dereference as deref
from cython.operator cimport preincrement as inc
from libc.stdint cimport uintptr_t, uint32_t
from ..graph cimport HarmatGraph, Node, NodeProperty, Nptr
from ..bglgraph cimport Graph
from ..extras cimport remove, find, make_pair
from ..path_finding cimport ag_all_simple_attack_paths
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
        self.cy_all_paths = find_attack_paths(deref(self.graph_ptr), self.source.np, nodes)


    def flowup(self):
        for node in self.hosts():
            node.flowup()

    @property
    def impact(self):
        self.check_attack_paths()
        cdef double cur_max = 0
        cdef double path_impact
        for path in self.cy_all_paths:
            path_impact = self.path_impact(path)
            if cur_max > path_impact:
                cur_max = path_impact
        return cur_max

    cdef double path_impact(self, vector[Nptr] path):
        if path.empty():
            return 0
        cdef double cur_sum = 0
        cdef vector[Nptr].iterator it = path.begin()
        cdef Nptr node
        inc(it)
        while it != path.end():
            node = deref(it)
            cur_sum += deref(it).impact
            inc(it)
        return cur_sum

    @property
    def all_paths(self):
        return [[<object>self.np_to_py[node] for node in path] for path in self.cy_all_paths]

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
        cdef double cur_max = 0
        cdef double pathrisk
        for path in self.cy_all_paths:
            pathrisk = self.path_risk(path)
            if pathrisk > cur_max:
                cur_max = pathrisk
        return cur_max

    @cython.wraparound(False)
    @cython.boundscheck(False)
    cdef double path_risk(self, vector[NodeProperty*] path):
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
        if path.empty():
            return 0
        cdef double path_risk_sum = 0
        cdef vector[Nptr].iterator it = path.begin()
        cdef Nptr node
        inc(it)
        while it != path.end():
            node = deref(it)
            path_risk_sum += node.risk * node.asset_value
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
        cdef vector[vector[Nptr]].iterator it = self.cy_all_paths.begin()
        cdef double cur_min = self.path_cost(self.cy_all_paths[0])
        inc(it)
        cdef double pathcost
        while it != self.cy_all_paths.end():
            pathcost = self.path_cost(deref(it))
            if pathcost < cur_min:
                cur_min = pathcost
            inc(it)
        return cur_min

    @cython.wraparound(False)
    cdef double path_cost(self, vector[NodeProperty*] path):
        """
        Calculate the cost of an attack for a single path

        Args:
            path : this is a list (or generator) containing a path =between two
            nodes

        Returns:
            The calculated cost value
        """
        if path.empty():
            return 0
        cdef double path_cost_sum = 0
        cdef Nptr node
        cdef vector[Nptr].iterator it = path.begin()
        inc(it)
        while it != path.end():
            node = deref(it)
            path_cost_sum += node.cost
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
        cdef double cur_max = 0
        cdef double pathroa
        for path in self.cy_all_paths:
            pathroa = self.path_return(path)
            if pathroa > cur_max:
                cur_max = pathroa
        return cur_max

    cdef double path_return(self, vector[Nptr] path):
        """
        probability, impact and cost attributes must be set for all nodes
        """
        if path.empty():
            return 0
        cdef double path_return = 0
        cdef vector[Nptr].iterator it = path.begin()
        cdef Nptr node
        inc(it)
        while it != path.end():
            node = deref(it)
            if node.cost == 0:
                raise Exception('Zero cost host is not permitted')
            path_return += node.risk / node.cost
            inc(it)
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
        path_len_generator = (path.size() - 1 for path in self.cy_all_paths)
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
        #TODO: Use Boost Graph here
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
        cdef vector[vector[Nptr]].iterator it = self.cy_all_paths.begin()
        cdef double cur_max = self.path_probability(deref(it))
        inc(it)
        cdef double pprob
        while it != self.cy_all_paths.end():
            pprob = self.path_probability(deref(it))
            if pprob > cur_max:
                cur_max = pprob
            inc(it)
        return cur_max

    cdef double path_probability(self, vector[Nptr] path):
        # return reduce(lambda x, y: x * y, (host.lower_layer.values['probability'] for host in path[1:]))
        cpdef double p = 1
        cdef vector[Nptr].iterator it = path.begin()
        inc(it)
        while it != path.end():
            prob = deref(it).probability
            if prob == 0:
                return 0
            p *= prob
            inc(it)
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

cdef inline bint is_vulnerable(NodeProperty* np) nogil:
    return np.probability != 0

@cython.wraparound(False)
@cython.boundscheck(False)
cdef vector[vector[Nptr]] find_attack_paths(Graph[NodeProperty]& G, NodeProperty* source, vector[Nptr] targets):
    cdef vector[vector[Nptr]] all_paths
    cdef vector[vector[Nptr]] new_paths
    for target in targets:
        if target != source:
            new_paths = ag_all_simple_attack_paths(G, source, target)
            for path in new_paths:
                all_paths.push_back(path)
    return all_paths


ctypedef vector[Nptr].iterator vit

@cython.wraparound(False)
@cython.boundscheck(False)
cdef vector[vector[Nptr]] all_simple_attack_paths(Graph[NodeProperty]& G, NodeProperty* source, NodeProperty* target) nogil:
    """
    Modified and cythonized version of NetworkX _all_simple_paths_graph
    Notably, this ignores hosts with no vulnerabilities and ignores ignorable set hosts.

    :param G: Attack graph
    :param source: source node
    :param target: target node
    :param cutoff:
    :return:
    """
    cdef Graph[NodeProperty] graph_ptr = G
    cdef uint32_t num_nodes = graph_ptr.num_vertices()
    cdef vector[vector[Nptr]] paths
    cdef uint32_t cutoff = num_nodes - 1
    cdef vector[Nptr] visited
    cdef vector[pair[vit, vit]] stack
    cdef unordered_set[NodeProperty*] traversed
    cdef vector[Nptr] new_path
    cdef Nptr child
    cdef vit* children
    cdef vit* children_end
    cdef vector[Nptr] out_nodes = graph_ptr.out_nodes(source)
    if num_nodes < 2:
        return paths
    visited.push_back(source)
    traversed.insert(source)
    stack.push_back(make_pair(out_nodes.begin(), out_nodes.end()))
    while stack.empty() == False:
        children = &(stack.back().first)
        children_end = &(stack.back().second)
        if deref(children) == deref(children_end):
            stack.pop_back()
            traversed.erase(visited.back())
            visited.pop_back()
        elif traversed.size() < cutoff:
            child = deref(deref(children))
            inc(deref(children))
            if child == target:
                new_path = vector[Nptr](visited)
                new_path.push_back(target)
                paths.push_back(new_path)
            elif traversed.find(child) == traversed.end() and (child.ignorable or is_vulnerable(child)):
                visited.push_back(child)
                traversed.insert(child)
                out_nodes = vector[Nptr](graph_ptr.out_nodes(child))
                stack.push_back(make_pair(out_nodes.begin(), out_nodes.end()))
        else:
            child = deref(deref(children))
            if child == target or find(deref(children), deref(children_end), target) != deref(children_end):
                new_path = vector[Nptr](visited)
                new_path.push_back(target)
                paths.push_back(new_path)
            stack.pop_back()
            traversed.erase(visited.back())
            visited.pop_back()
    return paths
