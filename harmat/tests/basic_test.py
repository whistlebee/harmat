from harmat import *

ag = AttackGraph()

# Create Hosts
hosts = [Host(str(i)) for i in range(5)]
for host in hosts:
    basic_vul = Vulnerability('CVE-TESTING', values={
        'risk': 5,
        'cost': 5,
        'probability': 0.2,
        'impact': 5,
    })
    host.lower_layer = AttackTree(host=host)
    host.lower_layer.basic_at([basic_vul])

ag.add_edge(hosts[0], hosts[1])
ag.add_edge(hosts[1], hosts[2])
ag.add_edge(hosts[2], hosts[3])
ag.add_edge(hosts[3], hosts[4])
ag.source = hosts[0]
ag.target = hosts[4]
ag.flowup()
ag.find_paths()
h = Harm()
h.top_layer = ag
print(list(psv_hybrid(h, 0.5)))