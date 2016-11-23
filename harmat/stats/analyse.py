import harmat as hm
import copy

def psv(h, percentage, method="topdown"):
    raise NotImplementedError()
    assert isinstance(h, hm.Harm)

def patch_vul_from_harm(h, vulname):
    """
    HARM in AG-AT.
    :param h: Harm
    :param vul: vul to patch
    """
    for node in h[0].nodes():
        node.lower_layer.patch_vulns([vulname])


def exhaustive(h):
    """
    Exhaustive Search Method for the Risk Metric
    :param h:  Harm
    :returns:
    """
    assert isinstance(h, hm.Harm)
    h = copy.deepcopy(h)
    h.flowup()
    system_risk = h.risk
    solution_set = []
    while system_risk > 0:
        current_risk = 0
        solution = None
        # find all vulnerabilities in the network
        all_vulnerabilities = []
        for host in h[0].nodes():
            for vul in host.lower_layer.all_vulns():
                if vul.name not in all_vulnerabilities:
                    all_vulnerabilities.append(vul.name)
        for vulname in all_vulnerabilities:
            h2 = copy.deepcopy(h)
            try:
                patch_vul_from_harm(h2, vulname)
                h2.flowup()
                new_system_risk = h2.risk
            except ValueError:
                new_system_risk = 0
            if new_system_risk > current_risk:
                current_risk = new_system_risk
                solution = vulname
                h = h2
        system_risk = current_risk
        if solution is not None:
            solution_set.append(solution)
    return solution_set






        



