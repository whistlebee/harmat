""""
@author: Paul Kim
hki34@uclive.ac.nz
"""

import networkx
import json
from node import *
from attackgraph import *
from attacktree import *

class Harm(object):
    """
    This class is the base class for Hierarchical Attack Representation
    Models(HARM)
    All layers should be inherited classes of the networkx graph class.
    This allows us to take advantage of its many features regarding graphs.

    How to use this class.
    ----------------------
    This class should be the main way to interact between the attack
    representation layers to reduce complexity in the codebase.

    E.g.

    from safelite.common.harm import *
    #Initialise Harm
    my_harm = Harm()

    #load data
    my_harm.load_json('examplenetwork.json')

    #Visualise the model
    visualise(myharm, 'harm.png', mode='save')

    NOTE: Although we can use many of networkx's functionalities, some may
    require some additional formatting to work with our implementations.
    """

    def __init__(self, initial_num_layers = None):
        """
        Initialisation. Make sure to update the self.num_layers attribute to
        improve performance.
        """
        top_layer = None

    def calculate_risk(self, source, target):
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

        return self.top_layer.calculate_risk(source, target)

    def calculate_cost(self, source, target):
        """
        Calculate the cost value of between target and source

        Args:
            source: the reference to the source node
            target: the reference to the target node
        """
        if type(self.top_layer) != AttackGraph:
            raise Exception("Top layer of HARM must be an AG")
        return self.top_layer.calculate_cost(source, target)

    def create_children_node(self, node):
        """
        Used only during importing json file
        Create a Node object which contains all the information which it contains
        for one (higher level) node
        Args:
            node a (higher level) node dictionary
        Returns:
            Node object
        """
        node_type = node['type']
        nn = None
        if node_type  == 'sibling':
            #case when it is a vulnerabiity
            nn = Vulnerability(node['name'])
            nn.id = node['id']
            nn.risk = node['value']
        elif node_type == 'or' or node_type == 'and':
            #case when it is a logic gate
            nn = LogicGate(node_type)
        return nn

    def recursively_add(self, child_json, parent_node, at):
        """
        Used only during importing json file
        Recursively add the tree into the lower layer attack tree.
        Args:
            child_json: the return after calling node['children']
            parent_node: the parent node. Used to to add to graph
            at: the AttackTree object to add to.
        """
        if child_json:
            nn = self.create_children_node(child_json)
            at.add_node(nn)
            at.add_edge(parent_node, nn)
            for child in child_json['children']:
                self.recursively_add(child, nn, at)

    def load_json(self, filename):
        """"
        Load old safelite example networks which are in JSON format
        The json format assumed the use of AG-AT two layer Harm.
        TODO: Should be deprecated/updated later on after further implementing
        N-HARM
        Args:
            filename: the filename of the desired JSON network
        """
        ag = AttackGraph()
        with open(filename) as data_file:
            data = json.load(data_file)
        #data is a dictionary. Key through all the 'nodes' in this dictionary
        #and we create node objects and add them to the attack graph.
        for node in data['nodes']:
            new_host = Host()
            new_host.name = node['name']
            new_host.id = node['id']
            new_host.risk = node['value']
            ll = AttackTree(None)
            new_host.lower_layer = ll
            new_host.lower_layer.rootnode = LogicGate("or") 
            if node['children']:
                self.recursively_add(node['children'][0], ll.rootnode, ll) 
            ag.add_node(new_host)
        for link in data['links']:
            ag.add_edge(ag.nodes()[link['source']], ag.nodes()[link['target']])
            ag.add_edge(ag.nodes()[link['target']], ag.nodes()[link['source']])
        self.top_layer = ag
        self.num_layers = 2

    def aggregate_ag(self, n_layers):
        """
        We aggregate n_layers of AG's so that we can apply metric calculations
        Args:
            n_layers
        """
        raise NotImplementedError()

