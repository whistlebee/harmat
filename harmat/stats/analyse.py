import harmat as hm

def psv(h, percentage, method="topdown"):
    raise NotImplementedError()
    assert isinstance(h, hm.Harm)


def exhaustive(h, metric):
    raise NotImplementedError()
    assert isinstance(h, hm.Harm)

    system_risk = 0
    solution_set = []
    while system_risk > 0:
        current_risk = 0
        solution = None

        # find all vulnerabilities in the network
        all_vulnerabilities = []
        for host in h[0].nodes():
            for vul in host.all_vulns:
                if vul not in all_vulnerabilities:
                    all_vulnerabilities.append(vul)

        



