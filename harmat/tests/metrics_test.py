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
    6 Hosts in total. Flowup done.
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


def testAG3():
    """
    Creates a AG object with Hosts with 1 vulnerability each
    6 Hosts in total. Flowup done.
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
    return [testAG1(), testAG2(), testAG3()]


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
        self.assertTrue(ag[2].mean_path_length() == 10.0/3.0)


if __name__ == '__main__':
    unittest.main()