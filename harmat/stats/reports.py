from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from future import standard_library

standard_library.install_aliases()
import harmat
from networkx import number_of_nodes, density
from tabulate import tabulate
from collections import OrderedDict
from harmat.stats.analyse import percentage_of_severe_systems


class Summary(object):
    def show(self):
        # Write a subclass for this
        raise NotImplementedError()


class SafeviewSummary(Summary):
    def __init__(self, harm):
        self.stats = OrderedDict()
        self.calculate(harm)

    def calculate(self, model):
        self.stats['Number of hosts'] = number_of_nodes(model[0])
        self.stats['Risk'] = model.risk
        self.stats['Cost'] = model.cost
        self.stats['Mean of attack path lengths'] = model[0].mean_path_length()
        self.stats['Mode of attack path lengths'] = model[0].mode_path_length()
        self.stats['Standard Deviation of attack path lengths'] = \
            model[0].stdev_path_length()
        self.stats['Shortest attack path length'] = model[0].shortest_path_length()
        self.stats['Return on Attack'] = model[0].return_on_attack()
        self.stats['Density'] = density(model[0])
        self.stats['Normalised Mean Path Length'] = model[0].normalised_mean_path_length()
        self.stats['Probability of attack success'] = model[0].probability_attack_success()
        self.stats['Number of Attack Paths'] = model[0].number_of_attack_paths()
        self.state['Percentage of severse systems'] = percentage_of_severe_systems(model)



class HarmSummary(Summary):
    def __init__(self, harm, show_progress=False):
        assert isinstance(harm, harmat.Harm)
        self.show_progress = show_progress
        self.compute_status = False
        self.stats = OrderedDict()
        self.compute(harm)
        self.model = harm

    def compute(self, model):
        if self.show_progress is True:
            print("Calculating Number of Hosts")
        self.stats['Number of hosts'] = number_of_nodes(model[0])
        if self.show_progress is True:
            print("Calculating Risk")
        self.stats['Risk'] = model.risk
        if self.show_progress is True:
            print("Calculating Cost")
        self.stats['Cost'] = model.cost
        if self.show_progress is True:
            print("Calculating Mean of Path lengths")
        self.stats['Mean of attack path lengths'] = model[0].mean_path_length()
        if self.show_progress is True:
            print("Calculating Mode of Path lengths")
        self.stats['Mode of attack path lengths'] = model[0].mode_path_length()
        if self.show_progress is True:
            print("Calculating Standard deviation")
        self.stats['Standard Deviation of attack path lengths'] = \
            model[0].stdev_path_length()
        if self.show_progress is True:
            print("Calculating attack path length")
        self.stats['Shortest attack path length'] = model[0].shortest_path_length()
        if self.show_progress is True:
            print("Calculating Return on Attack")
        self.stats['Return on Attack'] = model[0].return_on_attack()
        if self.show_progress is True:
            print("Calculating Density")
        self.stats['Density'] = density(model[0])
        self.compute_status = True

    def show(self, format="simple"):
        if self.compute_status is False:
            self.compute(self.model)
        data = [(k, v) for k, v in self.stats.items()]
        headers = ["Metrics", "Values"]
        print(tabulate(data, headers=headers, tablefmt=format))
