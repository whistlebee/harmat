try:
    from pomegranate.BayesianNetwork import BayesianNetwork
    from pomegranate.base import State
    from pomegranate.distributions import DiscreteDistribution, ConditionalProbabilityTable
except ImportError as e:
    import warnings
    warnings.warn('Pomegranate is not installed. Using Bayesian Harm will not work. {}'.format(e))
    # Ignore if pomegranate is not installed
    pass

from .attackgraph import AttackGraph
import itertools


class Harm:
    """
    This class is the base class for Hierarchical Attack Representation
    Models(HARM)
    """

    def __init__(self):
        self.top_layer = AttackGraph()

    def flowup(self):
        self.top_layer.flowup()

    def __getitem__(self, index):
        current_layer = self.top_layer
        for i in range(index):
            current_layer = [node.lower_layer for node in current_layer.nodes()]
        return current_layer

    def __repr__(self):
        return "{} Object".format(self.__class__.__name__)

    @property
    def risk(self):
        """
        Calcuate the risk value between a source and a target.
        Requires the top layer to be an Attack Graph
        For more information, look at the documentation for the risk
        calculation on the AttackTree module.

        Args:
            source: the reference to the source node
            target: the reference to the target node
        Returns:
            The value of the calculated risk
        Exceptions:
            Raises an error if the type of the top layer is not an AttackTree
        """

        # Check that the top layer is an attack tree
        if not isinstance(self.top_layer, AttackGraph):
            raise TypeError("Top layer of the HARM must be an AG")
        return self.top_layer.risk

    @property
    def cost(self):
        """
        Calculate the cost value of between target and source

        Args:
            source: the reference to the source node
            target: the reference to the target node
        """
        if not isinstance(self.top_layer, AttackGraph):
            raise TypeError("Top layer of HARM must be an AG")
        return self.top_layer.cost

    def aggregate_ag(self):
        """
        Combine the top AG layers into a single AG for metric calculation.
        Needed for N-HARM.
        """
        raise NotImplementedError()

    def bayesian_method(self):
        return BayesianMethod(self).generate_bayesian()


class BayesianMethod:
    def __init__(self, harm: Harm):
        self.harm = harm

    def table_generator(self, num_parent, prob):
        table = []
        for i in itertools.product([True, False], repeat=num_parent + 1):
            row = list(i)
            if sum(row[:num_parent]) == 0:
                row.append(1 - row[-1])
            else:
                if row[-1]:
                    row.append(prob)
                else:
                    row.append(1 - prob)
            table.append(row)
        return table

    def bayes_net(self, conditional_dict, current_node):
        """recursively back propagate through nodes"""
        if current_node in conditional_dict.keys():
            return

        if current_node == self.harm.top_layer.source:
            conditional_dict[current_node] = DiscreteDistribution({True: 1, False: 0})
            return

        if len(list(self.harm.top_layer.predecessors_iter(current_node))) == 0:
            conditional_dict[current_node] = DiscreteDistribution(
                {True: current_node.probability, False: 1 - current_node.probability})
            return

        parent_list = []
        for parent in self.harm.top_layer.predecessors_iter(current_node):
            self.bayes_net(conditional_dict, parent)
            parent_list.append(conditional_dict[parent])

        conditional_dict[current_node] = ConditionalProbabilityTable(
            self.table_generator(len(parent_list), current_node.probability), parent_list)

    def generate_bayesian(self):
        """
        Generates the bayesian network with pomegranate
        """
        conditional_dict = {}
        state_dict = {}
        self.bayes_net(conditional_dict, self.harm.top_layer.target)

        model = BayesianNetwork('B-Harm')
        host_list = []
        for index, node in enumerate(conditional_dict.keys()):
            state_dict[node] = State(conditional_dict[node], name=str(node))
            if node == self.harm.top_layer.target:
                target_index = index
            model.add_state(state_dict[node])
            host_list.append(node)

        for edge in self.harm.top_layer.edges():
            s, t = edge
            source = state_dict.get(s, None)
            target = state_dict.get(t, None)
            model.add_transition(source, target)

        model.bake()
        total = 0
        risk = 0
        roa = 0
        total_ac = 0

        for i in itertools.product([True, False], repeat=len(state_dict) - 1):
            scenario = list(i)
            scenario.insert(target_index, True)

            probability = model.probability(scenario)
            if probability <= 1e-4:
                continue

            total_impact = 0
            attack_cost = 0
            total_roa = 0
            for i, val in enumerate(scenario):
                if val is True:
                    total_impact += host_list[i].impact
                    attack_cost += host_list[i].cost
                    total_roa += host_list[i].impact / host_list[i].cost

            total_ac += probability * attack_cost
            total += probability
            risk += probability * total_impact
            roa += probability * total_roa

        return {
            'total': total,
            'ag_risk': risk,
            'roa': roa,
            'total_ac': total_ac
        }
