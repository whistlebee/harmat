from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from future import standard_library

standard_library.install_aliases()
import harmat as hm
import copy
import itertools
import math


def normalise_centrality_values(ag):
    """
    Normalise a given AttackGraph with respect to their centrality values
    :param list_to_normalise:
    """
    if not isinstance(ag, hm.AttackGraph):
        raise TypeError('Must be AttackGraph!')
    centrality_sum = sum(node.values['centrality'] for node in ag.nodes())
    for node in ag.nodes():
        node.values['centrality'] = node.values['centrality'] / centrality_sum


def psv_hybrid(h, percentage, alpha=0.5):
    """
    Prioritised Set of Vulnerabilities method of determining patch order
    :param h: Harm object
    :param percentage: top k percentage of vulnerabilities to choose (0 to 1)
    :param alpha: ratio between Top AG and Lower AT contribution ratio
    :return:
    """
    if not isinstance(h, hm.Harm):
        raise TypeError('Given object must be a HARM')
    harm = copy.deepcopy(h)
    harm.flowup()
    harm[0].initialise_centrality_measure()
    normalise_centrality_values(harm[0])
    list_of_vulns = []  # Host - Vuln 2-tuples
    for node in harm[0].nodes():
        vulns = [(node, vul) for vul in node.lower_layer.all_vulns()]
        for vuln_tuple in vulns:
            vuln_tuple[1].importance_measure = alpha * node.centrality + (1 - alpha) * node.risk
        list_of_vulns.extend(vulns)
    sorted_vulns = sorted(list_of_vulns, key=lambda x: x[1].importance_measure, reverse=True)
    psv = itertools.islice(sorted_vulns, math.ceil(percentage * len(list_of_vulns)))
    return psv


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
            except ValueError:  # When there are no more attack paths
                new_system_risk = 0
            if new_system_risk < current_risk:
                current_risk = new_system_risk
                solution = vul
        h = h2
        system_risk = current_risk
        if solution is not None:
            all_vulnerabilities.remove(solution)
            yield solution


if __name__ == '__main__':
    h = hm.generate_random_harm(50, 5, edge_prob=0.3)
