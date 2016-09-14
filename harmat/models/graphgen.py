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
    vulnerability.risk = random.randrange(0, 10)
    vulnerability.cvss = vulnerability.risk
    return vulnerability


def generate_lower_layer(vul_count):
    lower_layer = harmat.AttackTree()
    lower_layer.rootnode = harmat.LogicGate("or")
    name_counter = 0
    for i in range(vul_count):
        vul_name = "GeneratedVulnerability{}".format(name_counter)
        lower_layer.add_vuln(random_vulnerability(vul_name))
        name_counter += 1
    return lower_layer


def generate_top_layer(node_count, vul_count, graph_function, edge_prob=0.7):
    graph = graph_function(node_count, edge_prob, directed=True)
    graph.__class__ = harmat.AttackGraph
    counter = 0 #counter for node name
    for node in graph.nodes():
        new_host = harmat.Host(name="Host{}".format(counter))
        lower_layer = generate_lower_layer(vul_count)
        new_host.lower_layer = lower_layer
        replace_node(graph, node, new_host)
        counter += 1
    return graph


def generate_random_harm(node_count, vul_count, graph_function=networkx.fast_gnp_random_graph, edge_prob=0.7):
    """
    Generate a random HARM with the given properties
    :param node_count: Number of nodes in graph
    :param vul_count: Number of vulnerabilities per node
    :param graph_function: Choice of graph type. Use NetworkX graph generation. Defaults to Erdos-Renyi graph
    :return :
    """
    harm = harmat.Harm()
    harm.top_layer = generate_top_layer(node_count, vul_count, graph_function, edge_prob=edge_prob)
    return harm


if __name__ == "__main__":
    harm = generate_random_harm(15, 5, edge_prob=0.2)

    source, target = None, None
    for node in harm.top_layer.nodes():
        if node.name == "Host1":
            source = node
        if node.name == "Host5":
            target = node
    harm.calculate_risk(source, target)
    print("finished")
    print(networkx.readwrite.json_graph.node_link_data(harm.top_layer))








