""""
@author: Paul Kim
hki34@uclive.ac.nz
"""


from .attackgraph import *


class Harm(object):
    """
    This class is the base class for Hierarchical Attack Representation
    Models(HARM)
    All layers should be inherited classes of the networkx graph class.
    This allows us to take advantage of its many features regarding graphs.

    NOTE: Although we can use many of networkx's functionalities, some may
    require some additional formatting to work with our implementations.
    """

    def __init__(self):
        self.top_layer = None

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

        #Check that the top layer is an attack tree
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

