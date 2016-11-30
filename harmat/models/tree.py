from queue import Queue

class Tree:
    """
    Basic tree class to replace networkx.DiGraph for Attacktree
    May need to improve this if many insertions are being done.
    """
    def __init__(self):
        self.__rootnode = TreeNode(None)
        # undeclared_nodes is used to store nodes before edges are added.
        # we need this maintain compatibility with networkx.digraph
        self.undeclared_nodes = []

    def add_node(self, node):
        """
        Adds a node to the tree but no connection is specified.
        Must specify the connection using add_edge.
        :param node: anything
        """
        self.undeclared_nodes.append(node)

    def add_edge(self, parent, child):
        """
        Adds a edge between a child (from undeclared_nodes) to an existing node on the tree
        :param parent: A node existing on the tree
        :param child:  A node in undeclared_nodes
        """
        if child not in self.undeclared_nodes:
            raise LookupError("Node does not exist in undeclared nodes")
        tree_node_parent = self.find_node(parent)
        tree_node_child = TreeNode(child)
        tree_node_parent.children.append(tree_node_child)
        self.undeclared_nodes.remove(child)


    def find_node(self, node):
        """
        Uses DFS to look for node
        :param node: A node on the Tree
        :return: TreeNode where node is located
        """
        for tree_node in self.traverse():
            if tree_node.content == node:
                return tree_node
        raise LookupError("Given node does not exist on the tree")

    def traverse(self):
        """
        Uses BFS to traverse the tree
        :return: a generator which traverses the tree
        """
        nodes_to_visit = Queue()
        nodes_to_visit.put(self.__rootnode)
        while nodes_to_visit.empty() is False:
            current_node = nodes_to_visit.get()
            yield current_node
            for child in current_node.children:
                nodes_to_visit.put(child)

    def remove_node(self, node):
        for tree_node in self.traverse():
            if tree_node.content == node:
                tree_node.parent.children.remove(tree_node) # remove node from parent


    def nodes(self):
        """
        Traverses the tree in BFS fashion.
        :return: generator
        """
        return (node.content for node in self.traverse())

    def neighbors(self, node):
        return (tree_node.content for tree_node in self.find_node(node).children)

    def __getitem__(self, node):
        return self.neighbors(node)

    @property
    def rootnode(self):
        return self.__rootnode.content

    def parent(self, node):
        """
        Finds the parent node of the given node
        :param node: a node in the tree
        :return: parent of the node
        """
        return self.find_node(node).parent.content

    def __setattr__(self, key, value):
        """
        We need a custom __setattr__ method to set the rootnode value
        """
        if key == 'rootnode':
            self.__rootnode = TreeNode(value)
        else:
            self.__dict__[key] = value


class TreeNode:
    def __init__(self, content):
        self.children = []
        self.parent = None
        self.content = content

    def __eq__(self, other):
        if not isinstance(other, TreeNode):
            raise TypeError('Both must be TreeNode objects')
        if self.content == other.content:
            return True
        return False
