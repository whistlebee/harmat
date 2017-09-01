from libcpp.memory cimport unique_ptr
from libcpp cimport bool
from libcpp.vector cimport vector
from libcpp.pair cimport pair
from libc.stdint cimport uintptr_t
from cython.operator cimport dereference as deref
from cython.operator cimport preincrement as inc

cdef extern from "harmat_bgl.h" namespace "harmat":
    cdef cppclass Graph[T]:
        Graph() except +
        void add_vertex(T* np)
        void add_edge(T* np1, T* np2)
        void remove_vertex(T* node)
        vector[T*] nodes()
        vector[T*] out_nodes(T* node)
        vector[T*] in_nodes(T* node)

cdef struct NodeProperty:
    double risk
    double cost
    double impact
    double probability
    bool ignorable

cdef class PyBoostGraph:
    cdef unique_ptr[Graph[NodeProperty]] graph_ptr
    cdef object np_to_py

    def __cinit__(self):
        self.graph_ptr.reset(new Graph[NodeProperty]())
        self.np_to_py = dict()

    def __init__(self):
        pass

    def __iter__(self):
        """
        Iterate over the nodes
        :return: iterator
        """
        return self.nodes()


    def __contains__(self, Node n):
        """
        Return True if n is a node in the Graph
        :param n: Node
        :return: Boolean
        """
        #TODO: implement this in C++
        return n in self.nodes()

    def __getitem__(self, Node n):
        return self.successors(n)

    cpdef add_node(self, Node n):
        deref(self.graph_ptr).add_vertex(&n.np)
        self.np_to_py[<uintptr_t>&n.np] = n

    cpdef add_edge(self, Node source, Node target):
        deref(self.graph_ptr).add_edge(&source.np, &target.np)

    def add_nodes_from(self, nodes):
        map(self.add_node, nodes)

    cpdef remove_node(self, Node n):
        deref(self.graph_ptr).remove_vertex(&n.np)

    def nodes(self):
        cdef vector[NodeProperty*] np_vec = deref(self.graph_ptr).nodes();
        cdef vector[NodeProperty*].iterator it = np_vec.begin()
        while it != np_vec.end():
            yield(self.np_to_py[<uintptr_t>deref(it)])
            inc(it)

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
        #TODO: implement this in C++
        return u in self.predecessors(v)

    def successors_iter(self, Node n):
        """
        Return an iterator over successor nodes of n
        :param n: Node
        :return: Iterator
        """
        cdef vector[NodeProperty*] np_vec = deref(self.graph_ptr).out_nodes(&n.np);
        cdef vector[NodeProperty*].iterator it = np_vec.begin()
        while it != np_vec.end():
            yield(self.np_to_py[<uintptr_t>deref(it)])
            inc(it)

    def predecessors_iter(self, Node n):
        """
        Return an iterator over predecessor nodes of n
        :param n: Node
        :return: Iterator
        """
        cdef vector[NodeProperty*] np_vec = deref(self.graph_ptr).in_nodes(&n.np);
        cdef vector[NodeProperty*].iterator it = np_vec.begin()
        while it != np_vec.end():
            yield(self.np_to_py[<uintptr_t>deref(it)])
            inc(it)

    def successors(self, Node n):
        """
        Return a list of successor nodes of n
        Identical to neighbors()
        :param n: Node
        :return: list
        """
        return list(self.successors_iter)

    def predecessors(self, Node n):
        """
        Return a list of predecessor nodes of n
        :param n: Node
        :return: list
        """
        return list(self.predecessors_iter)

    def neighbors(self, Node n):
        """
        Return a list of successor nodes of n.
        Identical to successors()
        :param n: Node
        :return: list
        """
        return list(self.successors_iter)


cdef class Node:
    cdef NodeProperty np
    def __cinit__(self):
        self.np = NodeProperty(0, 0, 0, 0, False)

    def __init__(self, risk=1, cost=1, probability=1, impact=1, ignorable=False):
        self.risk = risk
        self.cost = cost
        self.probability = probability
        self.impact = impact

    @property
    def risk(self):
        return self.np.risk

    @risk.setter
    def risk(self, value):
        self.np.risk = value

    @property
    def cost(self):
        return self.np.cost

    @cost.setter
    def cost(self, value):
        self.np.cost = value

    @property
    def probability(self):
        return self.np.probability

    @probability.setter
    def probability(self, value):
        self.np.probability = value

    @property
    def impact(self):
        return self.np.impact

    @impact.setter
    def impact(self, value):
        self.np.impact = value
