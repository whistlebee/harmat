import harmat as hm

def test_bayesian():
    # initialise the harm
    h = hm.Harm()

    # create the top layer of the harm
    # top_layer refers to the top layer of the harm
    h.top_layer = hm.AttackGraph()

    # we will create 5 nodes and connect them in some way
    # first we create some nodes
    hosts = [hm.Host("Host {}".format(i)) for i in range(5)]
    # then we will make a basic attack tree for each
    for host in hosts:
        # We specify the owner of the AttackTree so that the
        # AttackTree's values can be directly interfaced from the host
        host.lower_layer = hm.AttackTree(host=host)
        # We will make two vulnerabilities and give some metrics
        vulnerability1 = hm.Vulnerability('CVE-0000', values={
            'risk': 10,
            'cost': 4,
            'probability': 0.9,
            'impact': 12
        })
        # basic_at creates just one OR gate and puts all vulnerabilites
        # the children nodes
        host.lower_layer.basic_at([vulnerability1])

    # Now we will create an Attacker. This is not a physical node but it exists to describe
    # the potential entry points of attackers.
    attacker = hm.Attacker()

    # To add edges we simply use the add_edge function
    # here h[0] refers to the top layer
    # add_edge(A,B) creates a uni-directional from A -> B.
    h[0].add_edge(attacker, hosts[0])
    h[0].add_edge(hosts[0], hosts[1])
    h[0].add_edge(hosts[0], hosts[2])
    h[0].add_edge(hosts[1], hosts[3])
    h[0].add_edge(hosts[2], hosts[3])
    h[0].add_edge(hosts[1], hosts[2])

    # Now we set the attacker and target
    h[0].source = attacker
    h[0].target = hosts[3]
    h.flowup()
    result = h.bayesian_method()
    epsilon = 1e-4
    assert abs(result['total'] - 0.8019) < epsilon
    assert abs(result['total_ac'] - 13.0491) < epsilon
    assert abs(result['ag_risk'] - 37.5435) < epsilon
    assert abs(result['roa'] - 9.9873) < epsilon


