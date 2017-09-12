from libcpp.memory cimport unique_ptr
from libcpp.unordered_map cimport unordered_map
from libcpp.unordered_set cimport unordered_set
from libcpp cimport bool
from libcpp.vector cimport vector
from libcpp.string cimport string
from cpython cimport PyObject
from bglgraph cimport Graph

cdef struct NodeProperty:
    double risk
    double cost
    double impact
    double probability
    double asset_value
    bool ignorable

cdef class Node:
    cdef NodeProperty* np
    cdef string _name

cdef class FusedNode(Node):
    cdef Node __parent

ctypedef NodeProperty* Nptr
ctypedef PyObject* PyObjptr

cdef class HarmatGraph:
    cdef unique_ptr[Graph[NodeProperty]] graph_ptr
    cdef unordered_map[Nptr, PyObjptr] np_to_py
    cdef unordered_set[Nptr] nodes_in_graph

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

cdef class DuplicableHarmatGraph(HarmatGraph):
    cpdef add_node(self, Node n)
