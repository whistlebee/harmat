import time
import harmat as hm

def large_test1():
    harm = hm.Harm()
    harm.top_layer = hm.AttackGraph()
    for i in range(10):
        h = hm.Host('Test'+str(i))
        try:
            h.lower_layer = hm.AttackTree(host=h)
        except:
            h.lower_layer = hm.AttackTree()
        v = hm.Vulnerability('CVE', values={
            'risk': 2,
            'cost': 1,
            'probability': 0.9,
            'impact': 1
        })
        h.lower_layer.basic_at([v])
        harm[0].add_node(h)
        harm[0].add_edge_between(h, list(harm[0].nodes()), two_ways=True)

    harm[0].source = list(harm[0].nodes())[0]
    harm[0].target = list(harm[0].nodes())[1]
    harm.flowup()
    harm[0].find_paths()
