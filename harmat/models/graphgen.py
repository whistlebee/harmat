from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from builtins import range

from future import standard_library

standard_library.install_aliases()
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
        'risk': random.randrange(1, 10),
        'cost': random.randrange(1, 10),
        'probability': random.randrange(0, 1),
        'impact': random.randrange(0, 10)
    }
    return vulnerability


def generate_lower_layer(vul_count):
    lower_layer = harmat.AttackTree()
    rootnode = harmat.LogicGate("or")
    lower_layer.rootnode = rootnode
    lower_layer.add_node(rootnode)
    for i in range(vul_count):
        vul_name = "GVE-{}".format(random.randint(0, 9999))
        lower_layer.at_add_node(random_vulnerability(vul_name))
    return lower_layer


def generate_top_layer(node_count, vul_count, graph_function, edge_prob=0.7):
    graph = graph_function(node_count, edge_prob, directed=True)
    graph.__class__ = harmat.AttackGraph
    graph.all_paths = None
    counter = 0  # counter for node name
    for node in graph.nodes():
        new_host = harmat.Host(name="Host{}".format(counter))
        lower_layer = generate_lower_layer(vul_count)
        new_host.lower_layer = lower_layer
        replace_node(graph, node, new_host)
        counter += 1
    return graph


def generate_random_harm(node_count=20, vul_count=5, graph_function=networkx.fast_gnp_random_graph, edge_prob=0.5):
    """
    Generate a random HARM with the given properties
    Does not guarantee source/target connection.
    :param node_count: Number of nodes in graph
    :param vul_count: Number of vulnerabilities per node
    :param graph_function: Choice of graph type. Use NetworkX graph generation. Defaults to Erdos-Renyi graph
    :return :
    """
    harm = harmat.Harm()
    harm.top_layer = generate_top_layer(node_count, vul_count, graph_function, edge_prob=edge_prob)
    harm.top_layer.source = harm.top_layer.nodes()[0]
    harm.top_layer.target = harm.top_layer.nodes()[1]
    return harm
