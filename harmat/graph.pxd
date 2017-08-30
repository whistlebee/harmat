from libcpp.memory cimport unique_ptr
from libcpp cimport bool
from libcpp.vector cimport vector
from bglgraph cimport Graph

cdef struct NodeProperty:
    double risk
    double cost
    double impact
    double probability
    double asset_value
    bool ignorable

ctypedef NodeProperty* Nptr

cdef class HarmatGraph:
    cdef unique_ptr[Graph[NodeProperty]] graph_ptr
    cdef object np_to_py

    cpdef add_node(self, Node n)

    cpdef add_edge(self, Node source, Node target)

    cpdef remove_node(self, Node n)

    cpdef has_successor(self, Node u, Node v)

    cpdef has_predecessor(self, Node u, Node v)

    cpdef successors(self, Node n)

    cpdef predecessors(self, Node n)

    cpdef neighbors(self, Node n)

    cpdef bool is_directed(self)

    cpdef unsigned int number_of_edges(self)

    cpdef unsigned int number_of_nodes(self)



cdef class Node:
    cdef NodeProperty* np;
