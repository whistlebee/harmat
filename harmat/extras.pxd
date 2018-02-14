"""
Small Cython interfaces for C++ functions
"""

from libcpp.pair cimport pair

cdef extern from "<initializer_list>" namespace "std" nogil:
    cdef cppclass initializer_list[T]

cdef extern from "<algorithm>" namespace "std" nogil:
    Iter remove[Iter, T](Iter first, Iter last, const T& val)
    T cpp_max[T](initializer_list[T] ilist)
    Iter find[Iter, T](Iter first, Iter last, const T& val)

cdef extern from "<utility>" namespace "std" nogil:
    pair[T1, T2] make_pair[T1, T2](T1 u, T2 v)



