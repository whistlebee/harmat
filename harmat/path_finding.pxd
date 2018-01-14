from libcpp.vector cimport vector
from .graph cimport Graph, NodeProperty, Nptr

cdef extern from 'path_finding.h' namespace 'harmat' nogil:
    vector[vector[Nptr]] ag_all_simple_attack_paths[NodeProperty](
        Graph[NodeProperty]& G, Nptr source, Nptr target)
