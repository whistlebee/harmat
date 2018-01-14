import time
from harmat import *


def test_large():
    harm = Harm()
    harm.top_layer = AttackGraph()
    for i in range(10):
        h = Host('Test' + str(i))
        try:
            h.lower_layer = AttackTree(host=h)
        except:
            h.lower_layer = AttackTree()
        v = Vulnerability('CVE', values={
            'risk': 2,
            'cost': 1,
            'probability': 0.9,
            'impact': 1
        })
        h.lower_layer.basic_at([v])
        harm[0].add_node(h)
        harm[0].add_edge_between(h, list(harm[0].nodes()), two_ways=True)

    harm[0].source = list(harm[0].nodes())[0]
    harm[0].target = list(harm[0].nodes())[1]
    harm.flowup()
    harm[0].find_paths()


def test_path_find():
    h = Harm()
    h.top_layer = AttackGraph()
    hosts = [Host(str(i)) for i in range(10)]
    attacker = Attacker()

    h[0].add_edge(attacker, hosts[0])
    h[0].add_edge(hosts[0], hosts[1])
    h[0].add_edge(hosts[0], hosts[6])
    h[0].add_edge(hosts[0], hosts[5])
    h[0].add_edge(hosts[1], hosts[8])
    h[0].add_edge(hosts[1], hosts[5])
    h[0].add_edge(hosts[1], hosts[4])
    h[0].add_edge(hosts[2], hosts[0])
    h[0].add_edge(hosts[2], hosts[6])
    h[0].add_edge(hosts[2], hosts[4])
    h[0].add_edge(hosts[3], hosts[9])
    h[0].add_edge(hosts[3], hosts[8])
    h[0].add_edge(hosts[3], hosts[1])
    h[0].add_edge(hosts[4], hosts[9])
    h[0].add_edge(hosts[4], hosts[6])
    h[0].add_edge(hosts[4], hosts[0])
    h[0].add_edge(hosts[5], hosts[7])
    h[0].add_edge(hosts[5], hosts[8])
    h[0].add_edge(hosts[5], hosts[6])
    h[0].add_edge(hosts[6], hosts[9])
    h[0].add_edge(hosts[6], hosts[8])
    h[0].add_edge(hosts[6], hosts[4])
    h[0].add_edge(hosts[7], hosts[6])
    h[0].add_edge(hosts[7], hosts[5])
    h[0].add_edge(hosts[7], hosts[4])
    h[0].add_edge(hosts[8], hosts[0])
    h[0].add_edge(hosts[8], hosts[3])
    h[0].add_edge(hosts[8], hosts[7])
    h[0].add_edge(hosts[9], hosts[1])
    h[0].add_edge(hosts[9], hosts[8])
    h[0].add_edge(hosts[9], hosts[6])
    h[0].source = attacker
    h[0].target = hosts[9]
    h[0].find_paths()

    assert len(h[0].all_paths) == 50
