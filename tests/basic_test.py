from harmat import *


def test_basic1():
    ag = AttackGraph()
    # Create Hosts
    hosts = [Host(str(i)) for i in range(5)]
    for host in hosts:
        basic_vul = Vulnerability('CVE-TESTING', values={
            'risk': int(host.name) + 0.1,
            'cost': 5,
            'probability': 0.2,
            'impact': 5,
        })
        host.lower_layer = AttackTree(host=host)
        host.lower_layer.basic_at([basic_vul])

    ag.add_edge(hosts[0], hosts[1])
    ag.add_edge(hosts[1], hosts[2])
    ag.add_edge(hosts[1], hosts[3])
    ag.add_edge(hosts[1], hosts[4])

    ag.source = hosts[0]
    ag.target = hosts[4]

    ag.flowup()
    ag.find_paths()
    assert ag.all_paths == [(hosts[0], hosts[1], hosts[4])]


def test_not_reachable():
    ag = AttackGraph()

    # Create Hosts
    hosts = [Host(str(i)) for i in range(5)]
    for host in hosts:
        basic_vul = Vulnerability('CVE-TESTING', values={
            'risk': int(host.name) + 0.1,
            'cost': 5,
            'probability': 0.2,
            'impact': 5,
        })
        host.lower_layer = AttackTree(host=host)
        host.lower_layer.basic_at([basic_vul])

    ag.source = hosts[0]
    ag.add_edge(hosts[0], hosts[1])
    ag.target = hosts[4]
    ag.flowup()
    ag.find_paths()
    assert ag.all_paths == []


def test_at_rootnode_override():
    host = Host('test')
    at = AttackTree()
    host.lower_layer = at
    v1 = Vulnerability('vul1', values={'risk': 10000})
    host.lower_layer.basic_at(v1)
    host.flowup()
    assert host.risk == 10000


def test_add_existing_edge():
    """
    Test that adding an existing edge doesn't break code
    """
    ag = AttackGraph()
    hosts = [Host(str(i)) for i in range(5)]
    for host in hosts:
        basic_vul = Vulnerability('CVE-TESTING', values={
            'risk': int(host.name) + 0.1,
            'cost': 5,
            'probability': 0.2,
            'impact': 5,
        })
        host.lower_layer = AttackTree(host=host)
        host.lower_layer.basic_at([basic_vul])

    ag.add_edge(hosts[0], hosts[1])
    ag.add_edge(hosts[0], hosts[1])
    ag.add_edge(hosts[1], hosts[2])
    ag.add_edge(hosts[1], hosts[3])
    ag.add_edge(hosts[1], hosts[4])

    ag.source = hosts[0]
    ag.target = hosts[4]
    ag.flowup()
    ag.find_paths()
    assert ag.all_paths == [(hosts[0], hosts[1], hosts[4])]


def test_multiple_targets():
    ag = AttackGraph()
    # Create Hosts
    hosts = [Host(str(i)) for i in range(5)]
    for host in hosts:
        basic_vul = Vulnerability('CVE-TESTING', values={
            'risk': int(host.name) + 0.1,
            'cost': 5,
            'probability': 0.2,
            'impact': 5,
        })
        host.lower_layer = AttackTree(host=host)
        host.lower_layer.basic_at([basic_vul])

    ag.add_edge(hosts[0], hosts[1])
    ag.add_edge(hosts[1], hosts[2])
    ag.add_edge(hosts[1], hosts[3])
    ag.add_edge(hosts[1], hosts[4])

    ag.source = hosts[0]

    ag.flowup()
    ag.find_paths()
    assert set(tuple(path) for path in ag.all_paths) == {
        (hosts[0], hosts[1]),
        (hosts[0], hosts[1], hosts[2]),
        (hosts[0], hosts[1], hosts[3]),
        (hosts[0], hosts[1], hosts[4])
    }


def test_remove_node():
    ag = AttackGraph()
    # Create Hosts
    hosts = [Host(str(i)) for i in range(5)]
    for host in hosts:
        basic_vul = Vulnerability('CVE-TESTING', values={
            'risk': int(host.name) + 0.1,
            'cost': 5,
            'probability': 0.2,
            'impact': 5,
        })
        host.lower_layer = AttackTree(host=host)
        host.lower_layer.basic_at([basic_vul])

    ag.remove_node(hosts[1])
    assert hosts[0] not in ag


def test_remove_edge():
    ag = AttackGraph()
    hosts = [Host(str(i)) for i in range(5)]
    for host in hosts:
        basic_vul = Vulnerability('CVE-TESTING', values={
            'risk': int(host.name) + 0.1,
            'cost': 5,
            'probability': 0.2,
            'impact': 5,
        })
        host.lower_layer = AttackTree(host=host)
        host.lower_layer.basic_at([basic_vul])

    ag.add_edge(hosts[0], hosts[1])
    assert (hosts[0], hosts[1]) in ag.edges()
    ag.remove_edge(hosts[0], hosts[1])
    assert (hosts[0], hosts[1]) not in ag.edges()


def test_add_nodes_from():
    ag = AttackGraph()
    num_nodes = 10
    hosts = [Host(str(i)) for i in range(num_nodes)]
    ag.add_nodes_from(hosts)
    assert len(list(ag.nodes())) == num_nodes