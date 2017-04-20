"""
These functions assume that all files are valid and all harms are also valid harms.
Later on, we need to incorporate N-HARM when it gets implemented.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from builtins import int
from builtins import open
from builtins import str
from six import iteritems

from future import standard_library

standard_library.install_aliases()
import harmat
import lxml.etree as ET
import uuid
import os.path


def parse_vulnerability_to_xml(at_node, at):
    if isinstance(at_node, harmat.Vulnerability):
        xml_vulnerability = ET.Element('vulnerability',
                                       attrib={
                                           'id': str(uuid.uuid4().int),
                                           'name': at_node.name
                                       })
        xml_values = ET.Element('vulner_values')
        for (key, value) in at_node.values.items():
            xml_value = ET.Element(key)
            xml_value.text = str(value)
            xml_values.append(xml_value)
        xml_vulnerability.append(xml_values)
    elif isinstance(at_node, harmat.LogicGate):
        xml_vulnerability = ET.Element(at_node.gatetype)
        for child in at[at_node]:
            xml_vulnerability.append(parse_vulnerability_to_xml(child, at))
    else:
        raise Exception("Weird class")
    return xml_vulnerability


def convert_node_to_xml(node):
    xml_node = ET.Element(
        'node', attrib={
            'id': str(uuid.uuid4().int),
            'name': node.name
        }
    )
    if isinstance(node, harmat.Attacker):
        return xml_node
    xml_values = ET.Element('host_values')
    for (key, value) in node.values.items():
        xml_value = ET.Element(key)
        xml_value.text = str(value)
        xml_values.append(xml_value)
    xml_node.append(xml_values)
    ig = ET.Element('ignorable')
    ig.text = str(node.ignorable)
    xml_node.append(ig)
    xml_vulnerabilities = ET.Element('vulnerabilities')
    if node.lower_layer:
        xml_vulnerabilities.append(parse_vulnerability_to_xml(node.lower_layer.rootnode,
                                                              node.lower_layer))
    xml_node.append(xml_vulnerabilities)
    return xml_node


def convert_edge_to_xml(s, t):
    xml_edge = ET.Element('edge')
    xml_source = ET.Element('source')
    xml_source.text = str(s)
    xml_edge.append(xml_source)

    xml_target = ET.Element('target')
    xml_target.text = str(t)
    xml_edge.append(xml_target)
    return xml_edge


def convert_to_xml(harm):
    """
    Convert a Harm object into a XML (ElementTree Element). Need to use write_to_file if you want to write to disk.
    :param harm:
    :return: ElementTree.Element
    """
    if not isinstance(harm, harmat.Harm):
        raise TypeError("Must pass a Harm as argument")
    xml_harm = ET.Element('harm')

    xml_nodes = ET.Element('nodes')
    node_order = []
    for node in harm.top_layer.nodes():
        xml_nodes.append(convert_node_to_xml(node))
        node_order.append(node)
    xml_harm.append(xml_nodes)

    xml_edges = ET.Element('edges')

    for (s, t) in harm.top_layer.edges():
        xml_edges.append(convert_edge_to_xml(node_order.index(s), node_order.index(t)))
    xml_harm.append(xml_edges)
    return xml_harm


def convert_psv_tuple_to_xml(psv_tuple):
    xml_tuple = ET.Element('psv_tuple')
    xml_host = ET.Element('host')
    xml_host.text = str(psv_tuple[0].name)
    xml_tuple.append(xml_host)
    xml_vuln = ET.Element('vulnerability')
    xml_vuln.text = str(psv_tuple[1].name)
    xml_tuple.append(xml_vuln)
    xml_value = ET.Element('value')
    xml_value.text = str(psv_tuple[1].importance_measure)
    xml_tuple.append(xml_value)
    return xml_tuple


def convert_summary_to_xml(summary, label='summaries'):
    """
    Convert a HarmSummary to ElementTree
    :param summary:
    :return:
    """
    xml_sum = ET.Element(label)
    for key, value in iteritems(summary.stats):
        xml_stat = ET.Element('summary', attrib={'name'  : str(key),
                                                 'value' : str(value)
                                                 })
        xml_sum.append(xml_stat)
    return xml_sum


def convert_to_safeview(harm, configs):
    """
    Converts a Harm object into a XML that contains necessary info for visualisations
    :param harm:
    :return:
    """

    if configs is None: # Default values
        configs = {
            'alpha' : 0.5,
            'percent': 0.2,
        }

    # Remove non-vulnerable hosts
    nodes_to_remove = []
    for node in harm[0].hosts():
        if not node.lower_layer.is_vulnerable():
            nodes_to_remove.append(node)
    for node in nodes_to_remove:
        harm[0].remove_node(node)

    attacker = harmat.Attacker()
    entry_points = configs.get('entry_points', None)
    if entry_points is not None: # if user specified entry points
        harm[0].add_node(attacker)
        for entry_point in entry_points:
            ep = harm[0].find_node(entry_point)
            if ep is not None:
                harm[0].add_edge(attacker, harm[0].find_node(entry_point))
    else:
        harm[0].add_edge_between(attacker, harm[0].nodes())
        harm[0].add_node(attacker)
    harm[0].source = attacker
    harm[0].flowup()
    harmat.stats.analyse.normalise_impact_values(harm[0])

    xml_harm = convert_to_xml(harm)

    # Add PSV Stuff
    xml_psv = ET.Element('psv_hybrid')
    tv = list(harmat.psv_hybrid(harm, configs['percent'], alpha=configs['alpha']))
    xml_psv.extend([convert_psv_tuple_to_xml(t) for t in tv])
    xml_harm.append(xml_psv)

    # Add summary stuff
    try:
        summary = harmat.SafeviewSummary(harm)
    except ValueError:
        return xml_harm

    xml_summary = convert_summary_to_xml(summary)
    xml_harm.append(xml_summary)
    # Patch top 20% vulnerabilities
    for v in tv:
        host = harm[0].find_node(v[0].name)
        host.lower_layer.patch_vul(v[1].name, is_name=True)
    harm.flowup()
    harm[0].find_paths()

    # Add after patching stuff
    summary2 = harmat.SafeviewSummary(harm)
    xml_summary2 = convert_summary_to_xml(summary2, label='summaries_patched')
    xml_harm.append(xml_summary2)
    return xml_harm

class XMLParseError(Exception): pass


def cut_crap(crap_string):
    return crap_string.tag.replace('{http://localhost:8000/safeview/harm}', '')


def parse_xml_attacktree(et, at, current_node=None):
    if cut_crap(et) == 'vulnerability':
        vul = harmat.Vulnerability(et.attrib['name'])
        if et[0]:
            vul.values = parse_values(et[0])
        if current_node is None:
            current_node, at.rootnode = vul, vul
            at.add_node(vul)
        else:
            at.at_add_node(vul, current_node)
    elif cut_crap(et) in ['or', 'and']:
        lg = harmat.LogicGate(cut_crap(et))
        if current_node is None:
            current_node, at.rootnode = lg, lg
            at.add_node(lg)
        else:
            at.at_add_node(lg, current_node)
        for child in et:
            parse_xml_attacktree(child, at, current_node=lg)
    else:
        raise XMLParseError("Unexpected value: {}".format(cut_crap(et)))


def parse_values(et):
    ret = {}
    for value in et:
        textval = value.text
        if textval == 'None':
            continue
        ret[cut_crap(value)] = float(value.text)
    return ret

def strtobool(stri):
    sl = stri.lower()
    if sl == 'true':
        return True
    elif sl == 'false':
        return False
    raise TypeError('invalid string')


# Gotta do something about this mess
def parse_xml(filename):
    """
    Convert an XML file containing the Harm into a harmat Harm object
    :param filename:
    :return: Harm
    """
    if not os.path.isfile(filename):
        raise IOError("File not found")

    harm = harmat.Harm()
    harm.top_layer = harmat.AttackGraph()
    with open(filename, 'rb') as file:
        tree = ET.parse(file)
        root = tree.getroot()
        host_list = []
        for root_elements in root:
            if cut_crap(root_elements) == 'nodes':
                for node in root_elements:
                    name = node.attrib['name']
                    if name == 'Attacker':
                        new_host = harmat.Attacker()
                        harm[0].source = new_host
                    else:
                        new_host = harmat.Host(node.attrib['name'])
                    for node_values in node:
                        if cut_crap(node_values) == 'ignorable':
                            new_host.ignorable = strtobool(node_values.text)
                        if cut_crap(node_values) == 'host_values':
                            new_host.values = parse_values(node_values)
                        if cut_crap(node_values) == 'vulnerabilities':
                            at = harmat.AttackTree()
                            if node_values:
                                parse_xml_attacktree(node_values[0], at)
                                new_host.lower_layer = at
                    harm.top_layer.add_node(new_host)
                    host_list.append(new_host)
            elif cut_crap(root_elements) == 'edges':
                for edge in root_elements:
                    if edge[0] is not None:
                        source = host_list[int(edge[0].text)]
                        target = host_list[int(edge[1].text)]
                        harm.top_layer.add_edge(source, target)
    return harm


def write_to_file(hxml, filename):
    """
    Write a ElementTree Element to a file
    :param hxml:
    :param filename:
    :return:
    """

    tree = ET.ElementTree(hxml)
    with open(filename, 'wb') as file:
        print('Writing..')
        tree.write(file)
        print('Written')
