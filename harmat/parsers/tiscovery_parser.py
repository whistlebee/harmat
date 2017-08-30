import json
import os
import harmat as hm


def tiscovery_parser(filename):
    if not os.path.isfile(filename):
        raise IOError("File not found")

    with open(filename, 'r') as jsonfile:
        parsed_json = json.loads(jsonfile.read())
    h = hm.Harm()
    h.top_layer = hm.AttackGraph()
    id_to_host_dict = {}  # A dictionary to store id -> host object mapping
    for node in parsed_json['nodes']:
        id = node['id']
        new_host = hm.Host(id)
        new_host.impact = node.get('impact')
        new_host.probability = node.get('probability')
        new_host.cost = node.get('cost')
        new_host.risk = node.get('risk')
        new_host.ignorable = node.get('ignorable', False)
        new_host.lower_layer = hm.AttackTree(host=new_host)
        vulns = []
        for vuln in node.get('vulnerabilities', {}):
            for key, val in vuln.items():
                harmat_vul = hm.Vulnerability(key, val)
                if harmat_vul.is_benign():
                    continue
                vulns.append(harmat_vul)
        new_host.lower_layer.basic_at(vulns)
        id_to_host_dict[id] = new_host
        h[0].add_node(new_host)

    for link in parsed_json['links']:
        source_id = link['source']
        target_id = link['target']
        # get back the harm objects
        source = id_to_host_dict[source_id]
        target = id_to_host_dict[target_id]
        h[0].add_edge(source, target)
    return h


if __name__ == '__main__':
    h = tiscovery_parser('../examplenets/data2.json')
    print(h[0].nodes())
    # from harmat import write_to_file, convert_to_xml
    # write_to_file(convert_to_xml(h), 'discoverytest.xml')
