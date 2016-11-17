import harmat
from networkx import number_of_nodes, density
from tabulate import tabulate
from collections import OrderedDict


class Summary(object):
    def show(self):
        # Write a subclass for this
        raise NotImplementedError()


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
            model[0].standard_deviation_path_length()
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
        data = [(k,v) for k,v in self.stats.items()]
        headers = ["Metrics", "Values"]
        print (tabulate(data, headers=headers, tablefmt=format))

