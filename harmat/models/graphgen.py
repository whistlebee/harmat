from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import random
import harmat
import networkx


def replace_node(graph, original_node, new_node):
    for p in graph.predecessors(original_node):
        graph.add_edge(p, new_node)
    for s in graph.successors(original_node):
        graph.add_edge(new_node, s)
    graph.remove_node(original_node)


def random_vulnerability(name):
    vulnerability = harmat.Vulnerability(name)
    vulnerability.values = {
        'risk': random.uniform(1, 10),
        'cost': random.uniform(1, 10),
        'probability': random.uniform(0, 1),
        'impact': random.uniform(0, 10)
    }
    return vulnerability


def generate_lower_layer(vul_count):
    lower_layer = harmat.AttackTree()
    rootnode = harmat.LogicGate("or")
    lower_layer.rootnode = rootnode
    lower_layer.add_node(rootnode)
    if vul_count == 0:
        return lower_layer
    for i in range(random.randrange(0,vul_count-1)):
        vul_name = "CVE-{}-{}".format(random.randint(2000, 2017), random.randint(0, 9999))
        lower_layer.at_add_node(random_vulnerability(vul_name))
    return lower_layer


def generate_top_layer(graph, vul_count):
    graph.__class__ = harmat.AttackGraph
    graph.all_paths = None
    counter = 0  # counter for node name
    for node in graph.nodes():
        new_host = harmat.Host(name="192.168.1.{}".format(counter))
        lower_layer = generate_lower_layer(vul_count)
        new_host.lower_layer = lower_layer
        replace_node(graph, node, new_host)
        counter += 1
    return graph


def generate_random_harm(node_count=20, vul_count=7, graph_function=networkx.fast_gnp_random_graph, edge_prob=0.5):
    """
    Generate a random HARM with the given properties
    Does not guarantee source/target connection.
    :param node_count: Number of nodes in graph
    :param vul_count: Number of vulnerabilities per node
    :param graph_function: Choice of graph type. Use NetworkX graph generation. Defaults to Erdos-Renyi graph
    :return :
    """
    harm = harmat.Harm()
    graph = graph_function(node_count, edge_prob, directed=True)
    harm.top_layer = generate_top_layer(graph, vul_count)
    attacker = harmat.Attacker()
    replace_node(harm[0], harm[0].nodes()[0], attacker)
    harm.top_layer.source = attacker
    harm.top_layer.target = harm.top_layer.nodes()[1]
    return harm


def random_harm_barbasi_albert(node_count, vul_count,edges):
    harm = harmat.Harm()
    graph = networkx.barabasi_albert_graph(node_count, edges)
    graph = graph.to_directed()
    harm.top_layer = generate_top_layer(graph, vul_count)
    attacker = harmat.Attacker()
    harm.top_layer.add_node(attacker)
    harm.top_layer.add_edge(attacker, graph.nodes()[0])
    harm[0].source = attacker
    return harm

def karate_club(vul_count):
    harm = harmat.Harm()
    graph = networkx.karate_club_graph()
    graph = graph.to_directed()
    harm.top_layer = generate_top_layer(graph, vul_count)
    attacker = harmat.Attacker()
    harm.top_layer.add_node(attacker)
    harm.top_layer.add_edge(attacker, graph.nodes()[0])
    harm[0].source = attacker
    return harm


def florentine_families(vul_count):
    harm = harmat.Harm()
    graph = networkx.florentine_families_graph()
    graph = graph.to_directed()
    harm.top_layer = generate_top_layer(graph, vul_count)
    attacker = harmat.Attacker()
    harm.top_layer.add_node(attacker)
    harm.top_layer.add_edge(attacker, graph.nodes()[0])
    harm[0].source = attacker
    return harm


if __name__ == '__main__':
    h = florentine_families(10)

    attacker = None
    for host in h[0].nodes():
        #host.lower_layer = None
        if isinstance(host, harmat.Attacker):
            attacker = host
    h[0].remove_node(attacker)
    harmat.write_to_file(harmat.convert_to_xml(h), '/Users/hjkim/Desktop/misc/safeview/data/Demo/vultest.xml')