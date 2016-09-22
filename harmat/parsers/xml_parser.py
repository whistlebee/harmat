import harmat
import xml.etree.cElementTree as ET
import uuid


def parse_vulnerability_to_xml(at_node, at):
    if isinstance(at_node, harmat.Vulnerability):
        xml_vulnerability = ET.Element('vulnerability',
            attrib={
                'id': uuid.uuid4(),
                'name': at_node.vulname
            })
        xml_values = ET.Element('values')
        xml_value = ET.Element('risk')
        xml_values.append(xml_value)
        xml_vulnerability.append(xml_values)
    elif isinstance(at_node, harmat.LogicGate):
        xml_vulnerability = ET.Element(at_node.gatetype)
        for child in at[at_node]:
            xml_vulnerability.append(parse_vulnerability_to_xml(child, at))
    else:
        raise Exception("")
    return xml_vulnerability


def convert_node_to_xml(node):
    xml_node = ET.Element(
        'node', attrib={
            'id': uuid.uuid4(),
            'name': node.name
        }
    )

    xml_values = ET.Element('values')
    xml_value = ET.Element('risk')
    xml_value.text = str(node.lower_layer.rootnode.risk)
    xml_values.append(xml_value)
    xml_node.append(xml_values)

    xml_vulnerabilities = ET.Element('vulnerabilities')
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

