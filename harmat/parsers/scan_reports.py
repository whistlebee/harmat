# Currently VERY Broken
import os

import safelite
from attackgraph import *
from attacktree import *
from harm import *
from safelite.interpreter.harm import *
from safelite.parsers.reportparser import *

TEMP_FILENAME = "tempag.mm"

def find_by_id(code, host_list):
    for host in host_list:
        if host is None:
            continue
        if host.id_ == code:
            return host
    return None


def handle_tree(node, at):
    name = node.name.split(VALUE_DELIMITER)[1]
    if node.type == 'sibling':
        new_node = Vulnerability(name)
        new_node.risk = float(node.name.split(VALUE_DELIMITER)[0]) * 10
    elif node.type == 'node':
        new_node = LogicGate(name.lower())
    at.add_node(new_node)
    at.add_edge(node, new_node)
    if at.rootnode is None:
        at.rootnode = new_node
    for c in node.children:
        handle_tree(c, at)

def generate_harm_from_openvas_report(openvas_report):
    """
    Generates a Harm object based on the file specified.

    Args:
        openvas_report: A string containing the location to the openvas report
    Returns:
        Harm() object
    """
    create_attackgraph_from_openvas(openvas_report, TEMP_FILENAME)
    old_harm = attackgraph_to_harm(TEMP_FILENAME, TEMP_FILENAME)
    mm = trim_mindmap(read_mindmap_from_file(TEMP_FILENAME))
    os.remove(TEMP_FILENAME)
    node = mindmap_to_model(mm)
    nodes = safelite.interpreter.harm._serialize_model(node, [])
    new_harm = Harm()
    new_harm.top_layer = AttackGraph()
    hosts = []
    #filter out hosts
    for n in nodes:
        if HOST_DELIMITER in n.name:
            hosts.append(n)
    #add all nodes to attack top layer
    for n in hosts:
        new_host = Host()
        new_host.name = n.name.split(HOST_DELIMITER)[0]
        new_host.risk = float(n.name.split(HOST_DELIMITER)[0]) * 10
        new_host.id_ = n.id
        new_harm.top_layer.add_node(new_host)
    for n in hosts:
        source = find_by_id(n.id, new_harm.top_layer.nodes())
        for c in n.children:
            #case where the child is a host. i.e. just a link
            if HOST_DELIMITER in c.name:
                target = find_by_id(c.id, new_harm.top_layer.nodes())
                new_harm.top_layer.add_edge(source, target)
            else:
                #case where the child is a logic gate
                ll = AttackTree()
                handle_tree(c, ll)
                source.lower_layer = ll
    return new_harm

if __name__=="__main__":
    report_large = "../../openvas_lib/tests/openvas_generic.xml"
    report = "../../openvas_lib/tests/openvas_generic_small.xml"
    report2 = "../../tests/safelite/hosts.xml"
    agfile = "../../tests/safelite/agtest.mm"
    harmfile = "../../tests/safelite/harmtest.mm"
    test_harm = generate_harm_from_openvas_report(report2)
    test_harm.visualise('test.png', mode='save')
