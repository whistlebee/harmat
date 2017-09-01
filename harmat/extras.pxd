cdef extern from "<initializer_list>" namespace "std" nogil:
    cdef cppclass initializer_list[T]

cdef extern from "<algorithm>" namespace "std" nogil:
    Iter remove[Iter, T](Iter first, Iter last, const T& val)
    T cpp_max[T](initializer_list[T] ilist)


