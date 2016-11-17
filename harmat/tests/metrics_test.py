from harmat import AttackGraph, Host, AttackTree, Vulnerability
import unittest


def testAG1():
    """
    Creates a AG object with Hosts with 1 vulnerability each
    5 Hosts in total. Flowup done.
    :return:  AG object
    """

    ag = AttackGraph()

    #Create Hosts
    hosts = [Host(str(i)) for i in range(5)]
    for host in hosts:
        basic_vul = Vulnerability('CVE-TESTING', values={
            'risk' : 5,
            'cost' : 5,
            'probability' : 0.2,
            'impact' : 5,
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
    5 Hosts in total. Flowup done.
    :return:  AG object
    """

    ag = AttackGraph()

    #Create Hosts
    hosts = [Host(str(i)) for i in range(6)]
    for host in hosts:
        basic_vul = Vulnerability('CVE-TESTING', values={
            'risk' : 5,
            'cost' : 5,
            'probability' : 0.2,
            'impact' : 5,
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


def testAGs():
    return [testAG1(), testAG2()]


class AGMetricsTestCase(unittest.TestCase):
    """
    Tests for metrics implemented in attackgraph.py
    """

    def test_risk(self):
        """ Test the risk"""
        ag = testAGs()
        self.assertTrue(ag[0].risk, 20)
        self.assertTrue(ag[1].risk, 25)

    def test_cost(self):
        ag = testAGs()
        self.assertTrue(ag[0].cost, 20)
        self.assertTrue(ag[1].cost, 20)

if __name__ == '__main__':
    unittest.main()