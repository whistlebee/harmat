from ..graph cimport DuplicableHarmatGraph, PyObjptr, Node
from libcpp.unordered_map cimport unordered_map
from libcpp.string cimport string

cdef class AttackTree(DuplicableHarmatGraph):
    cdef unordered_map[string, PyObjptr] name_to_vul

    cdef public object rootnode

    cpdef add_node(self, Node node)

    cpdef remove_node(self, Node node)

    cpdef find_vul_by_name(self, vulname)
