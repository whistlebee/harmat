from harmat import *


def test_reverse_graph():
    g = HarmatGraph()
    n1 = Host('1')
    n1.risk = 1
    n2 = Host('2')
    n2.risk = 2
    g.add_edge(n1, n2)
    r = g.reverse()
    print('reversed')
    print(r.edges())

test_reverse_graph()
