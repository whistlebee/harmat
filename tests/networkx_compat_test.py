import networkx as nx
from harmat import *

def instantiate_graphs():
    graph_types = (AttackGraph, nx.DiGraph)
    graphs = [g() for g in graph_types]
    return graphs

def build_graph_type1(graph, hosts):
    graph.add_edge(hosts[0], hosts[1])
    graph.add_edge(hosts[1], hosts[2])
    graph.add_edge(hosts[1], hosts[3])
    graph.add_edge(hosts[1], hosts[4])

def test_centrality():
    graphs = instantiate_graphs()
    hosts = [Host(str(i)) for i in range(5)]
    for g in graphs:
        build_graph_type1(g, hosts)
    centralities = (nx.degree_centrality,
                    nx.closeness_centrality,
                    nx.betweenness_centrality)
    # Calculate centralities
    ag_cents, nx_cents = [[cent(g) for cent in centralities] for g in graphs]
    assert ag_cents == nx_cents

def test_adj():
    graphs = instantiate_graphs()
    hosts = [Host(str(i)) for i in range(5)]
    for g in graphs:
        build_graph_type1(g, hosts)
    ag_adj, nx_adj = (g.adj for g in graphs)
    ag__adj, nx__adj = (g._adj for g in graphs)
    ag__succ, nx__succ = (g._succ for g in graphs)
    ag__pred, nx__pred = (g._pred for g in graphs)

    assert ag__adj == nx__adj
    assert ag_adj == nx_adj
    assert ag__succ == nx__succ
    assert ag__pred == nx__pred

def test_getitem():
    graphs = instantiate_graphs()
    hosts = [Host(str(i)) for i in range(5)]
    for g in graphs:
        build_graph_type1(g, hosts)
    test_host = hosts[1]
    ag, nx = graphs
    assert ag[test_host] == nx[test_host]
