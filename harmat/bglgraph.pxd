from libcpp.vector cimport vector
from libcpp.pair cimport pair

cdef extern from 'bglgraph.h' namespace 'harmat' nogil:
    cdef cppclass Graph[T]:
        ctypedef T* Tptr
        Graph() except +
        unsigned int num_vertices()
        void add_vertex(T* np)
        void add_edge(T* np1, T* np2)
        void remove_vertex(T* node)
        vector[T*] nodes()
        vector[T*] out_nodes(T* node)
        vector[T*] in_nodes(T* node)
        vector[pair[Tptr, Tptr]] edges()
        vector[pair[Tptr, Tptr]] in_edges(T* node)
        vector[pair[Tptr, Tptr]] out_edges(T* node)