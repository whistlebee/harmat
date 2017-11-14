from harmat import *

def basic_test1():
    ag = AttackGraph()
    # Create Hosts
    hosts = [Host(str(i)) for i in range(5)]
    for host in hosts:
        basic_vul = Vulnerability('CVE-TESTING', values={
            'risk': int(host.name)+0.1,
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
    assert ag.all_paths == [hosts[0], hosts[1], hosts[4]]

def basic_test2():
    ag = AttackGraph()

    # Create Hosts
    hosts = [Host(str(i)) for i in range(5)]
    for host in hosts:
        basic_vul = Vulnerability('CVE-TESTING', values={
            'risk': int(host.name)+0.1,
            'cost': 5,
            'probability': 0.2,
            'impact': 5,
        })
        host.lower_layer = AttackTree(host=host)
        host.lower_layer.basic_at([basic_vul])

    #hosts[1].ignorable = True
    ag.add_edge(hosts[0], hosts[1])
    hosts[1].ignorable = True
    ag.source = hosts[0]
    ag.target = hosts[4]
    ag.flowup()
    ag.find_paths()
    assert ag.all_paths == [hosts[0], hosts[1], hosts[4]]


def test_at_rootnode_override():
    host = Host('test')
    at = AttackTree()
    host.lower_layer = at
    v1 = Vulnerability('vul1', values={'risk': 10000})
    host.lower_layer.basic_at(v1)
    host.flowup()

    assert host.risk == 10000



