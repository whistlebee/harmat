"""
A conversion script for converting JSON formatted HARMs to XML variations.

python3 convert.py [-i] <input_file> [<output_file>]

"""

import json
import sys
from pathlib import Path
import xml.etree.cElementTree as eTree


def read_json(json_str):
    json_harm = json.loads(json_str)
    nodes = []
    edges = []

    for json_node in json_harm['nodes']:
        nodes.append({
            'id': json_node['id'],
            'name': json_node['name'],
            'values': {
                'impact': json_node['value']
            },
            # Will be [] for 'Attacker' - and will handle odd multi-roots
            'vulnerabilities': [read_json_vulnerability(root) for root in json_node['children']]
        })

    for json_edge in json_harm['links']:
        edges.append({
            'source': json_edge['source'],
            'target': json_edge['target'],
            'values': {}
        })

    harm = {
        'nodes': nodes,
        'edges': edges,
        'upperLayer': []
    }
    return harm


def read_json_vulnerability(json_vulnerability):
    if json_vulnerability['type'] == 'sibling':
        return {
            'id': json_vulnerability['id'],
            'name': json_vulnerability['name'],
            'type': 'vulnerability',
            'values': {
                'poe': json_vulnerability['value']
            }
        }
    else:  # json_vulnerability['type'] is in ['or', 'and']:
        return {
            'id': json_vulnerability['id'],
            'name': json_vulnerability['name'],
            'type': json_vulnerability['type'],
            'children': [read_json_vulnerability(child) for child in json_vulnerability['children']]
        }


def read_xml(xml_str):
    pass


def parse_json(harm):
    pass


def parse_xml(harm):
    # Create the root harm element
    xml_harm = eTree.Element(
        'harm', attrib={
            'xmlns':
                'http://localhost:8000/safeview/harm',
            'xmlns:xsi':
                'http://www.w3.org/2001/XMLSchema-instance',
            'xsi:schemaLocation':
                'http://localhost:8000/safeview/harm http://localhost:8000/static/safeviewservice/xml/harm.xsd',
        })

    # <nodes>
    xml_nodes = eTree.Element('nodes')
    for node in harm['nodes']:
        xml_nodes.append(convert_node_to_xml(node))
    xml_harm.append(xml_nodes)

    # <edges>
    xml_edges = eTree.Element('edges')
    for edge in harm['edges']:
        xml_edges.append(convert_edge_to_xml(edge))
    xml_harm.append(xml_edges)

    # <upperLayers>
    xml_upper_layers = eTree.Element('upperLayers')
    xml_harm.append(xml_upper_layers)
    return xml_harm


def convert_node_to_xml(node):
    xml_node = eTree.Element(
        'node', attrib={
            'id': node['id'],
            'name': node['name']
        })

    # <values>
    xml_values = eTree.Element('values')
    for key, value in node['values'].items():
        # <value>
        xml_value = eTree.Element(key)
        xml_value.text = str(value)
        xml_values.append(xml_value)
    xml_node.append(xml_values)

    # <vulnerabilities>
    xml_vulnerabilities = eTree.Element('vulnerabilities')
    if node['name'] != 'Attacker' and len(node['vulnerabilities']) > 0:
        root_vulnerability = node['vulnerabilities'][0]
        xml_vulnerabilities.append(parse_vulnerability_to_xml(root_vulnerability))
    xml_node.append(xml_vulnerabilities)

    return xml_node


def convert_edge_to_xml(edge):
    xml_edge = eTree.Element('edge')

    xml_source = eTree.Element('source')
    xml_source.text = str(edge['source'])
    xml_edge.append(xml_source)

    xml_target = eTree.Element('target')
    xml_target.text = str(edge['target'])
    xml_edge.append(xml_target)

    # <values>
    xml_values = eTree.Element('values')
    for key, value in edge['values'].items():
        # <value>
        xml_value = eTree.Element(key)
        xml_value.text = str(value)
        xml_values.append(xml_value)

    xml_edge.append(xml_values)
    return xml_edge


def parse_vulnerability_to_xml(vulnerability):
    if vulnerability['type'] in ['vulnerability', 'sibling']:
        # <vulnerability name id>
        xml_vulnerability = eTree.Element('vulnerability',
            attrib={
                'id': vulnerability['id'],
                'name': vulnerability['name']
            })
        # <values>
        xml_values = eTree.Element('values')
        for key, value in vulnerability['values'].items():
            # <value>
            xml_value = eTree.Element(key)
            xml_value.text = str(value)
            xml_values.append(xml_value)
        xml_vulnerability.append(xml_values)

    else:  # vulnerability.type is in ['or', 'and']:
        # <and> | <or>
        xml_vulnerability = eTree.Element(vulnerability['type'])
        for child in vulnerability['children']:
            # Recurse
            xml_vulnerability.append(parse_vulnerability_to_xml(child))

    return xml_vulnerability


def json_to_xml(json_str):
    harm = read_json(json_str)
    print(harm)
    return parse_xml(harm)


def main(argv):
    if len(argv) > 0:
        return run_json_to_xml(argv)
    else:
        prompt_usage()


def run_json_to_xml(argv):
    print(argv)
    if len(argv) == 0:
        # prompt
        prompt_usage()
        return
    else:  # len(argv) >= 1:
        for arg in argv:
            json_path = Path(arg)
            if not json_path.exists():
                prompt("Input file \"%s\" does not exist" % str(arg))
            elif not json_path.is_file():
                prompt("Input path does not point to a file")
            elif len(json_path.name) < 5 and json_path.name[-5:] != '.json':
                prompt("Input path is not a json file")
                # Potentially offer to continue regardless? y/n prompt
            else:  # consider validated
                prompt("Converting \"%s\" to xml" % str(arg))
                output_xml_path = Path(json_path.parent.joinpath(json_path.name[:-5] + '.xml'))
                json_str = ''
                for line in json_path.open(mode='r').readlines():
                    json_str += line
                xml_root_element = json_to_xml(json_str)
                eTree.ElementTree(xml_root_element).write(str(output_xml_path))
                prompt("Saved to \"%s\"" % str(output_xml_path))
            return


def prompt(text):
    print(text)


def prompt_usage():
    print("usage: python3 convert.py [json files ...]")


if __name__ == "__main__":
    main(sys.argv[1:])
