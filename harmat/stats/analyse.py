import harmat as hm
import copy
from networkx import number_of_nodes

def psv(h, percentage, method="topdown"):
    raise NotImplementedError()
    assert isinstance(h, hm.Harm)

def patch_vul_from_harm(h, vul):
    """
    HARM in AG-AT.
    :param h: Harm
    :param vul: vul to patch
    """
    for node in h[0].nodes():
        node.lower_layer.patch_vul(vul, is_name=True)

def exhaustive(h):
    """
    Exhaustive Search Method for the Risk Metric
    :param h:  Harm
    :returns: generator of vuls in order to patch
    """
    assert isinstance(h, hm.Harm)
    h = copy.deepcopy(h)
    h.flowup()
    system_risk = h.risk
    while system_risk > 0:
        current_risk = system_risk
        print(current_risk)
        solution = None
        # find all vulnerabilities in the network
        all_vulnerabilities = []
        for host in h[0].nodes():
            for vul in host.lower_layer.all_vulns():
                if vul not in all_vulnerabilities:
                    all_vulnerabilities.append(vul)
        for vul in all_vulnerabilities:
            h2 = copy.deepcopy(h)
            try:
                patch_vul_from_harm(h2, vul)
                h2.flowup()
                h2[0].find_paths()
                new_system_risk = h2.risk
            except ValueError:
                new_system_risk = 0
            if new_system_risk < current_risk:
                current_risk = new_system_risk
                solution = vul
        h = h2
        system_risk = current_risk
        if solution is not None:
            all_vulnerabilities.remove(solution)
            yield solution



        



