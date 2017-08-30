cdef extern from "<algorithm>" namespace "std" nogil:
    Iter remove[Iter, T](Iter first, Iter last, const T& val)
