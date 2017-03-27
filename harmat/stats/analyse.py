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
from networkx import number_of_nodes


def normalise_centrality_values(ag):
    """
    Normalise a given AttackGraph with respect to their centrality values
    :param list_to_normalise:
    """
    if not isinstance(ag, hm.AttackGraph):
        raise TypeError('Must be AttackGraph!')
    centrality_min = min(node.values['centrality'] for node in ag.nodes())
    centrality_max = max(node.values['centrality'] for node in ag.nodes())
    for node in ag.hosts():
        node.values['centrality'] = (node.values['centrality'] - centrality_min) / (centrality_max - centrality_min)


def normalise_risk_values(ag):
    if not isinstance(ag, hm.AttackGraph):
        raise TypeError('Must be AttackGraph!')
    risk_min = min(node.risk for node in ag.hosts())
    risk_max = max(node.risk for node in ag.hosts())
    for node in ag.hosts():
        if risk_min == 0 and risk_max == 0:
            node.values['risk'] = 0
        else:
            node.values['risk'] = (node.risk - risk_min) / (risk_max - risk_min)


def normalise_impact_values(ag):
    if not isinstance(ag, hm.AttackGraph):
        raise TypeError('Must be AttackGraph')
    impact_min = min(node.impact for node in ag.hosts())
    impact_max = max(node.impact for node in ag.hosts())
    for node in ag.hosts():
        node.impact = (node.impact - impact_min) / (impact_max - impact_min)


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
    normalise_risk_values(harm[0])
    list_of_vulns = []  # Host - Vuln 2-tuples
    for node in harm[0].hosts():
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


def mean_cost_to_mitigate(number_of_vuls, required_hours, hourly_rate, other_costs):
    return number_of_vuls * (required_hours * hourly_rate + other_costs) / number_of_vuls


def percentage_of_severe_systems(h):
    num_severe_systems = sum(1 for vul in (node.lower_layer.all_vulns for node in h[0].nodes()) if vul.risk >= 7)
    return num_severe_systems / number_of_nodes(h[0])


if __name__ == '__main__':
    h = hm.generate_random_harm(50, 5, edge_prob=0.3)
