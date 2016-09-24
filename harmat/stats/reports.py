import harmat
from networkx import number_of_nodes, density
import pprint
from tabulate import tabulate

class Summary(object):
    def show(self):
        # Write a subclass for this
        raise NotImplementedError()


class HarmSummary(Summary):
    def __init__(self, harm):
        assert isinstance(harm, harmat.Harm)
        self.compute_status = False
        self.stats = {}
        self.compute(harm)
        self.model = harm

    def compute(self, model):
        self.stats['Number of hosts'] = number_of_nodes(model[0])
        self.stats['Risk'] = model.risk
        self.stats['Cost'] = model.cost
        self.stats['Mean of attack path lengths'] = model[0].mean_path_length()
        self.stats['Mode of attack path lengths'] = model[0].mode_path_length()
        self.stats['Standard Deviation of attack path lengths'] = \
            model[0].standard_deviation_path_length()
        self.stats['Shortest attack path length'] = model[0].shortest_path_length()
        self.stats['Return on Attack'] = model[0].return_on_attack()
        self.stats['Density'] = density(model[0])
        self.compute_status = True

    def show(self, format="fancy_grid"):
        if self.compute_status is False:
            self.compute(self.model)
        data = [(k,v) for k,v in self.stats.items()]
        headers = ["Metrics", "Values"]
        print (tabulate(data, headers=headers, tablefmt=format))
        #pprint.pprint(self.stats)

