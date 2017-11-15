import pstats, cProfile
import harmat as hm


def create_benchmark_harm1():
    vul1 = hm.Vulnerability('CVE-TEST', values={
        'risk': 10,
        'cost': 10,
        'probability': 0.2,
        'impact': 10
        })
    vul2 = hm.Vulnerability('CVE-TEST2', values={
        'risk': 13,
        'cost': 12,
        'probability': 0.4,
        'impact': 12
        })
    vul3 = hm.Vulnerability('CVE-TEST2', values={
        'risk': 14,
        'cost': 18,
        'probability': 0.41,
        'impact': 12
        })
    harm = hm.Harm()
    harm.top_layer = hm.AttackGraph()
    hosts = [hm.Host(str(i)) for i in range(11)]
    prev = None
    for host in hosts:
        harm.top_layer.add_node(host)
        host.lower_layer = hm.AttackTree()
        host.lower_layer.basic_at([vul1, vul2, vul3])
        for ohost in hosts:
            harm.top_layer.add_edge(host, ohost)

    attacker = hm.Attacker()
    harm.top_layer.add_node(attacker)
    harm.top_layer.add_edge(attacker, hosts[0])
    harm.top_layer.source = attacker
    return harm

def benchmark(harm: hm.Harm):
    harm.flowup()
    harm[0].find_paths()
    harm.risk
    harm.cost

bench_harm1 = create_benchmark_harm1()
cProfile.runctx('benchmark(bench_harm1)', globals(), locals(), "Profile.prof")
s = pstats.Stats('Profile.prof')
s.strip_dirs().sort_stats('time').print_stats()
