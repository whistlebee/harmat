import harmat
import xml.etree.ElementTree as ET
import uuid
import os.path


def parse_vulnerability_to_xml(at_node, at):
    if isinstance(at_node, harmat.Vulnerability):
        xml_vulnerability = ET.Element('vulnerability',
            attrib={
                'id': str(uuid.uuid4().int),
                'name': at_node.name
            })
        xml_values = ET.Element('values')
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

    xml_values = ET.Element('values')
    for (key, value) in node.values.items():
        xml_value = ET.Element(key)
        xml_value.text = str(value)
        xml_values.append(xml_value)
    xml_node.append(xml_values)

    xml_vulnerabilities = ET.Element('vulnerabilities')
    if node.lower_layer:
        xml_vulnerabilities.append(parse_vulnerability_to_xml(node.lower_layer.rootnode,
                                                          node.lower_layer))
    xml_node.append(xml_vulnerabilities)
    return xml_node

def convert_edge_to_xml(s,t):
    xml_edge = ET.Element('edge')
    xml_source = ET.Element('source')
    xml_source.text = str(s)
    xml_edge.append(xml_source)

    xml_target = ET.Element('target')
    xml_target.text = str(t)
    xml_edge.append(xml_target)
    return xml_edge

def convert_to_xml(harm):
    if not isinstance(harm, harmat.Harm):
        raise TypeError("Must pass a Harm as argument")
    xml_harm = ET.Element(
        'harm', attrib={
            'xmlns':
                'http://localhost:8000/safeview/harm',
            'xmlns:xsi':
                'http://www.w3.org/2001/XMLSchema-instance',
            'xsi:schemaLocation':
                'http://localhost:8000/safeview/harm http://localhost:8000/static/safeviewservice/xml/harm.xsd',
        })
    xml_harm = ET.Element('harm')

    xml_nodes = ET.Element('nodes')
    node_order = []
    for node in harm.top_layer.nodes():
        xml_nodes.append(convert_node_to_xml(node))
        node_order.append(node)
    xml_harm.append(xml_nodes)

    xml_edges = ET.Element('edges')

    for (s,t) in harm.top_layer.edges():
        xml_edges.append(convert_edge_to_xml(node_order.index(s),node_order.index(t)))
    xml_harm.append(xml_edges)
    return xml_harm

class XMLParseError(Exception): pass

def cut_crap(crap_string):
    return crap_string.tag.replace("{http://localhost:8000/safeview/harm}", "")

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
    return {cut_crap(value): float(value.text) for value in et}

#Gotta do something about this mess
def parse_xml(filename):
    if not os.path.isfile(filename):
        raise IOError("File not found")

    harm = harmat.Harm()
    harm.top_layer = harmat.AttackGraph()
    with open(filename, 'r') as file:
        tree = ET.parse(file)
        root = tree.getroot()
        host_list = []
        for root_elements in root:
            if cut_crap(root_elements) == 'nodes':
                for node in root_elements:
                    new_host = harmat.Host(node.attrib['name'])
                    for node_values in node:
                        if cut_crap(node_values) == 'values':
                            new_host.values = parse_values(node_values)
                        if cut_crap(node_values) == 'vulnerabilities':
                            at = harmat.AttackTree()
                            if node_values:
                                parse_xml_attacktree(node_values[0], at)
                                new_host.lower_layer = at
                    harm.top_layer.add_node(new_host)
                    host_list.append(new_host)
            elif cut_crap(root_elements) == "edges":
                for edge in root_elements:
                    if edge[0] is not None:
                        source = host_list[int(edge[0].text)]
                        target = host_list[int(edge[1].text)]
                        harm.top_layer.add_edge(source, target)
    return harm

def write_to_file(hxml, filename):
    tree = ET.ElementTree(hxml)
    tree.write(open(filename, 'w'))









