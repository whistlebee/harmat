from libcpp cimport bool
from libcpp.memory cimport unique_ptr
from libcpp.vector cimport vector
from libcpp.pair cimport pair
from libcpp.unordered_map cimport unordered_map
from libcpp.string cimport string
from cython.operator cimport dereference as deref
from cython.operator cimport preincrement as inc
from libc.stdint cimport uintptr_t, uint32_t
from cpython cimport PyObject
from cpython.mem cimport PyMem_Malloc, PyMem_Free
from cpython.ref cimport Py_INCREF, Py_DECREF, Py_XDECREF
from bglgraph cimport Graph
from graph cimport NodeProperty, Nptr, PyObjptr, HarmatGraph, Node
from collections import OrderedDict

from networkx.classes.coreviews import AdjacencyView
from networkx.classes.reportviews import OutEdgeView, InEdgeView, \
    DiDegreeView, InDegreeView, OutDegreeView, NodeView, EdgeView


cdef class HarmatGraph:
    def __cinit__(self):
        self.graph_ptr.reset(new Graph[NodeProperty]())
        self.np_to_py = unordered_map[Nptr, PyObjptr]()
        self.nodes_in_graph = unordered_set[Nptr]()

    def __init__(self):
        pass

    def __iter__(self):
        """
        Iterate over the nodes
        :return: iterator
        """
        return iter(self.nodes())

    def __contains__(self, Node n):
        """
        Return True if n is a node in the Graph
        :param n: Node
        :return: Boolean
        """
        #TODO: implement this in Cython
        return not self.nodes_in_graph.find(n.np) == self.nodes_in_graph.end()

    def __getitem__(self, Node n):
        return OrderedDict((s, {}) for s in self.successors(n))

    @property
    def adj(self):
        return AdjacencyView(self._adj)

    @property
    def _adj(self):
        return OrderedDict((a, OrderedDict((b, {}) for b in self.successors_iter(a))) for a in self._node)

    @property
    def _node(self):
        # node properties are not stored here in harmat but we need this for
        # networkx compatibility
        cdef vector[NodeProperty*] np_vec = deref(self.graph_ptr).nodes()
        return {<object> self.np_to_py[np]: {} for np in np_vec}

    @property
    def _succ(self):
        return OrderedDict((a, OrderedDict((b, {}) for b in self.successors_iter(a))) for a in self._node)

    @property
    def _pred(self):
        return OrderedDict((a, OrderedDict((b, {}) for b in self.predecessors_iter(a))) for a in self._node)

    @property
    def pred(self):
        return AdjacencyView(self._pred)

    @property
    def succ(self):
        return AdjacencyView(self._succ)

    def degree(self):
        return DiDegreeView(self)

    cpdef add_node(self, Node n):
        if self.nodes_in_graph.find(n.np) == self.nodes_in_graph.end():
            Py_INCREF(n)
            deref(self.graph_ptr).add_vertex(n.np)
            self.nodes_in_graph.insert(n.np)
            self.np_to_py[n.np] = <PyObject*>n

    cpdef add_edge(self, Node source, Node target):
        # add to graph if source/target is not in the graph
        if self.nodes_in_graph.find(source.np) == self.nodes_in_graph.end():
            self.add_node(source)
        if self.nodes_in_graph.find(target.np) == self.nodes_in_graph.end():
            self.add_node(target)
        deref(self.graph_ptr).add_edge(source.np, target.np)

    def add_nodes_from(self, nodes):
        for node in nodes:
            self.add_node(node)

    cpdef remove_node(self, Node n):
        deref(self.graph_ptr).remove_vertex(n.np)
        self.np_to_py.erase(n.np)
        self.nodes_in_graph.erase(n.np)
        Py_DECREF(n)

    cpdef remove_edge(self, Node n1, Node n2):
        deref(self.graph_ptr).remove_edge(n1.np, n2.np)

    def nodes(self):
        return NodeView(self)

    cpdef has_successor(self, Node u, Node v):
        """
        Return True if node u has successor v.
        :param u: Node
        :param v: Node
        :return: Boolean
        """
        #TODO: implement this in C++
        return u in self.successors(v)

    cpdef has_predecessor(self, Node u, Node v):
        """
        Return True if node u has predecessor v.
        :param u: Node
        :param v: Node
        :return: Boolean
        """
        #TODO: implement this in Cython
        return u in self.predecessors(v)

    def successors_iter(self, Node n):
        """
        Return an iterator over successor nodes of n
        :param n: Node
        :return: Iterator
        """
        cdef vector[NodeProperty*] np_vec = deref(self.graph_ptr).out_nodes(n.np);
        for np in np_vec:
            yield <object>self.np_to_py[np]

    def predecessors_iter(self, Node n):
        """
        Return an iterator over predecessor nodes of n
        :param n: Node
        :return: Iterator
        """
        cdef vector[NodeProperty*] np_vec = deref(self.graph_ptr).in_nodes(n.np);
        for np in np_vec:
            yield <object>self.np_to_py[np]

    cpdef successors(self, Node n):
        """
        Return a list of successor nodes of n
        Identical to neighbors()
        :param n: Node
        :return: list
        """
        return list(self.successors_iter(n))

    cpdef predecessors(self, Node n):
        """
        Return a list of predecessor nodes of n
        :param n: Node
        :return: list
        """
        return list(self.predecessors_iter(n))

    cpdef neighbors(self, Node n):
        """
        Return a list of successor nodes of n.
        Identical to successors()
        :param n: Node
        :return: list
        """
        return list(self.successors_iter(n))

    cpdef unsigned int number_of_nodes(self):
        """
        Return the number of nodes in the graph
        :return: Number
        """
        return deref(self.graph_ptr).num_vertices()

    def edges(self):
        cdef vector[pair[Nptr, Nptr]] edges = deref(self.graph_ptr).edges()
        cdef vector[pair[Nptr, Nptr]].iterator it = edges.begin()
        while it != edges.end():
            edge = deref(it)
            if self.nodes_in_graph.find(edge.first) == self.nodes_in_graph.end() or \
                self.nodes_in_graph.find(edge.second) == self.nodes_in_graph.end():
                inc(it)
                continue
            yield (<object>self.np_to_py[edge.first],
                <object>self.np_to_py[edge.second])
            inc(it)

    cpdef unsigned int number_of_edges(self):
        cdef vector[pair[Nptr, Nptr]] edges = deref(self.graph_ptr).edges()
        return edges.size()

    def __len__(self):
        """
        Return the number of nodes in the graph
        :return: Number
        """
        return self.number_of_nodes()

    cpdef bint is_directed(self):
        return True

    def is_multigraph(self):
        return False

    def degree_iter(self, nbunch=None, weight=None):
        if weight is not None:
            raise NotImplementedError('Edge weights are not implemented')

        if nbunch is None:
            nodes = self.nodes()
        else:
            nodes = nbunch

        nodes_nbrs = ((n, self.predecessors(n) + self.successors(n)) for n in nodes)

        for n, nbrs in nodes_nbrs:
            yield (n, len(nbrs) + (n in nbrs))  # return tuple (n,degree)

    def adjacency_iter(self):
        adj = ((n, OrderedDict((succ, {}) for succ in self.successors(n))) for n in self.nodes())
        return iter(adj)


cdef class Node:
    def __cinit__(self):
        self.np = <NodeProperty*> PyMem_Malloc(sizeof(NodeProperty))
        self.initialise_memory()

    cdef initialise_memory(self):
        self.np.ignorable = False
        self.np.risk = 1
        self.np.cost = 1
        self.np.impact = 1
        self.np.probability = 1
        self.np.asset_value = 1

    def __init__(self, values=None, ignorable=False, name=''):
        if values is not None and isinstance(values, dict):
            self.update_values(values)
        self.name = name

    def __dealloc__(self):
        PyMem_Free(self.np)

    def update_values(self, value_dict):
        for key, item in value_dict.items():
            setattr(self, key, item)

    @property
    def name(self):
        return self._name.decode('utf-8')

    @name.setter
    def name(self, new_name):
        self._name = <string>new_name.encode('utf-8')


    @property
    def values(self):
        return {
            'risk': self.risk,
            'cost': self.cost,
            'impact': self.impact,
            'probability': self.probability
        }

    @property
    def risk(self):
        return deref(self.np).risk

    @property
    def cost(self):
        return deref(self.np).cost

    @property
    def impact(self):
        return deref(self.np).impact

    @property
    def probability(self):
        return deref(self.np).probability

    @property
    def asset_value(self):
        return deref(self.np).asset_value

    @property
    def ignorable(self):
        return deref(self.np).ignorable

    @risk.setter
    def risk(self, double val):
        deref(self.np).risk = val

    @cost.setter
    def cost(self, double val):
        deref(self.np).cost = val

    @impact.setter
    def impact(self, double val):
        deref(self.np).impact = val

    @probability.setter
    def probability(self, double val):
        deref(self.np).probability = val

    @ignorable.setter
    def ignorable(self, bool val):
        deref(self.np).ignorable = val

    @asset_value.setter
    def asset_value(self, double val):
        deref(self.np).asset_value = val

cdef class FusedNode(Node):
    def __cinit__(self):
        # Override to not allocate memory
        pass

    def __dealloc__(self):
        # Override to not try to free non-allocated memory address
        pass

    def __init__(self, Node fusenode):
        self.__parent = fusenode # Used to make sure self.np is memory safe
        self.np = fusenode.np

cdef class DuplicableHarmatGraph(HarmatGraph):
    def __init__(self):
        super(DuplicableHarmatGraph, self).__init__()

    cpdef add_node(self, Node n):
        Py_INCREF(n)
        deref(self.graph_ptr).add_vertex(n.np)
        self.nodes_in_graph.insert(n.np)
        self.np_to_py[n.np] = <PyObject*>n
