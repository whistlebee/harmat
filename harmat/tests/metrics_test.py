from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from builtins import range
from builtins import str

from future import standard_library

standard_library.install_aliases()
from harmat import AttackGraph, Host, AttackTree, Vulnerability, LogicGate, Harm, Attacker
import unittest


def testAG1():
    """
    Creates a AG object with Hosts with 1 vulnerability each
    5 Hosts in total. Flowup done.
    :return:  AG object
    """

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
        host.lower_layer = AttackTree()
        host.lower_layer.basic_at([basic_vul])

    ag.add_edge(hosts[0], hosts[1])
    ag.add_edge(hosts[1], hosts[2])
    ag.add_edge(hosts[2], hosts[3])
    ag.add_edge(hosts[3], hosts[4])
    ag.source = hosts[0]
    ag.target = hosts[4]

    ag.flowup()

    return ag


def testAG2():
    """
    Creates a AG object with Hosts with 1 vulnerability each
    6 Hosts in total. Flowup done.
    :return:  AG object
    """

    ag = AttackGraph()

    # Create Hosts
    hosts = [Host(str(i)) for i in range(6)]
    for host in hosts:
        basic_vul = Vulnerability('CVE-TESTING', values={
            'risk': 5,
            'cost': 5,
            'probability': 0.2,
            'impact': 5,
        })
        host.lower_layer = AttackTree()
        host.lower_layer.basic_at([basic_vul])

    ag.add_edge(hosts[0], hosts[1])
    ag.add_edge(hosts[1], hosts[2])
    ag.add_edge(hosts[2], hosts[3])
    ag.add_edge(hosts[3], hosts[4])
    ag.add_edge(hosts[3], hosts[5])
    ag.add_edge(hosts[5], hosts[4])

    ag.source = hosts[0]
    ag.target = hosts[4]

    ag.flowup()

    return ag


def testAG3():
    """
    Creates a AG object with Hosts with 1 vulnerability each
    6 Hosts in total. Flowup done.
    :return:  AG object
    """

    ag = AttackGraph()

    # Create Hosts
    hosts = [Host(str(i)) for i in range(6)]
    for host in hosts:
        basic_vul = Vulnerability('CVE-TESTING', values={
            'risk': 5,
            'cost': 5,
            'probability': 0.2,
            'impact': 5,
        })
        host.lower_layer = AttackTree()
        host.lower_layer.basic_at([basic_vul])

    ag.add_edge(hosts[0], hosts[1])
    ag.add_edge(hosts[1], hosts[2])
    ag.add_edge(hosts[2], hosts[3])
    ag.add_edge(hosts[3], hosts[4])
    ag.add_edge(hosts[3], hosts[5])
    ag.add_edge(hosts[5], hosts[4])
    ag.add_edge(hosts[0], hosts[4])

    ag.source = hosts[0]
    ag.target = hosts[4]

    ag.flowup()

    return ag


def testAGs():
    """
    Returns a list of AttackGraphs for testing
    testAG1 - 5 Identical Hosts connected in a line
    testAG2 - 6 Hosts connected like AG1 but two extra edges between (3->5), (5->4)
    testAG3 - 6 Hosts connected like AG2 but extra connection between (0->4)
    :return:
    """
    ags = [testAG1(), testAG2(), testAG3()]
    for attackgraph in ags:
        attackgraph.find_paths()
    return ags


class AGMetricsTestCase(unittest.TestCase):
    """
    Tests for metrics implemented in attackgraph.py
    """

    def test_risk(self):
        """ Test the risk"""
        ag = testAGs()
        self.assertTrue(ag[0].risk == 20)
        self.assertTrue(ag[1].risk == 25)
        self.assertTrue(ag[2].risk == 25)

    def test_cost(self):
        """
        Tests the cost calculation function
        """
        ag = testAGs()
        self.assertTrue(ag[0].cost == 20)
        self.assertTrue(ag[1].cost == 20)
        self.assertTrue(ag[2].cost == 5)

    def test_shortest_path_length(self):
        """
        Tests the length of the shortest path
        """
        ag = testAGs()
        self.assertTrue(ag[0].shortest_path_length() == 4)
        self.assertTrue(ag[1].shortest_path_length() == 4)
        self.assertTrue(ag[2].shortest_path_length() == 1)

    def test_mode_path_length(self):
        """
        Tests the mode of path calculation
        """
        ag = testAGs()
        self.assertTrue(ag[0].mode_path_length() == 4)
        self.assertTrue(ag[1].mode_path_length() == 5)
        self.assertTrue(ag[2].mode_path_length() == 5)

    def test_mean_path_length(self):
        """
        Tests the mean of paths metric
        :return:
        """
        ag = testAGs()
        self.assertTrue(ag[0].mean_path_length() == 4)
        self.assertTrue(ag[1].mean_path_length() == 4.5)
        self.assertTrue(ag[2].mean_path_length() == 10.0 / 3.0)


def testAT1():
    at = AttackTree()
    basic_vul1 = Vulnerability('CVE-TESTING0', values={
        'risk': 5,
        'cost': 5,
        'probability': 0.2,
        'impact': 5,
    })
    basic_vul2 = Vulnerability('CVE-TESTING2', values={
        'risk': 10,
        'cost': 10,
        'probability': 0.5,
        'impact': 8,
    })
    basic_vul3 = Vulnerability('CVE-TESTING3', values={
        'risk': 1,
        'cost': 1,
        'probability': 0.1,
        'impact': 2,
    })
    basic_lg = LogicGate('or')
    at.basic_at([basic_vul1, basic_vul2, basic_lg])
    at.at_add_node(basic_vul3, logic_gate=basic_lg)
    return at


def testATs():
    return [testAT1()]


class ATMetricsTestCase(unittest.TestCase):
    """
    Test the calculation methods for the AttackTree class
    """

    def test_flowup(self):
        at = testATs()
        at[0].flowup()
        correct_values_dict = {
            'risk': 10,
            'cost': 1,
            'impact': 8
        }
        for k, v in correct_values_dict.items():
            self.assertEqual(v, at[0].rootnode.values[k])


def pathtestHarm1():
    h = Harm()
    h.top_layer = AttackGraph()
    h[0].add_nodes_from([Host(str(i)) for i in range(5)])
    hosts = h[0].nodes()
    v0 = Vulnerability("BenignVul", values={
        'risk': 0,
        'probability': 0,
        'cost': 1,
        'impact': 1
    })
    v1 = Vulnerability("DangerVul", values={
        'risk': 10,
        'probability': 0.5,
        'cost': 1,
        'impact': 10
    })
    for i in range(0, 5):
        hosts[i].lower_layer = AttackTree()
        ll = hosts[i].lower_layer
        if i == 0:
            ll.basic_at(v0)
        else:
            ll.basic_at(v1)
    h[0].add_edge(hosts[0], hosts[1])
    h[0].add_edge(hosts[1], hosts[2])
    h[0].add_edge(hosts[2], hosts[3])
    h[0].add_edge(hosts[3], hosts[4])
    h[0].add_edge(hosts[0], hosts[4])
    attacker = Attacker()
    h[0].add_edge(attacker, hosts[0])
    h[0].source = attacker
    h[0].target = hosts[4]
    return h

def pathtestHarm2():
    h = pathtestHarm1()
    n = Host("Island")
    n.lower_layer = AttackTree()
    n.lower_layer.basic_at(Vulnerability('TEST', values = {
        'risk': 1,
        'cost': 1,
        'probability': 1,
        'impact': 1
    }))
    h[0].add_node(n)
    return h


'''
class PathCalcFixTestCase(unittest.TestCase):
    """
    Test that the no path scenario has been fixed
    """

    def test_error_handling(self):
        h1 = pathtestHarm1()
        h1[0].flowup()
        h1[0].find_paths()
        self.assertEqual(len(h1[0]), 0)
'''


if __name__ == '__main__':
    unittest.main()
