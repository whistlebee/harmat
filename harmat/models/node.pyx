from harmat.graph import FusedNode, Node

class Vulnerability(Node):
    def __init__(self, name, values=None, *args, **kwargs):
        super(Vulnerability, self).__init__(values=values)
        self.name = name

    def is_benign(self):
        if self.risk * self.probability == 0:
            return True
        return False

    def __repr__(self):
        return '{}:{}'.format(self.__class__.__name__, self.name)


class LogicGate(Node):
    VALID_GATES = ['or', 'and']
    def __init__(self, gatetype='or'):
        super(LogicGate, self).__init__(self)
        if self.validate_gatetype(gatetype) is False:
            raise TypeError('Invalid gatetype')
        self.gatetype = gatetype

    def validate_gatetype(self, gt):
        """
        Check that the gatetype string is a valid one

        Args:
            gt: The string to input check
        Returns:
            Boolean.
        """
        if gt not in self.VALID_GATES:
            return False
        return True

    def __repr__(self):
        return '{}:{}'.format(self.__class__.__name__, self.gatetype)

class RootNode(LogicGate, FusedNode):
    def __init__(self, gatetype = 'or', n = None):
        LogicGate.__init__(self, gatetype=gatetype)
        FusedNode.__init__(self, fusenode=n)

class Host(Node):
    def __init__(self, name, values=None):
        super(Host, self).__init__(values=values)
        self.name = name
        self.lower_layer = None

    def flowup(self):
        self.lower_layer.flowup()

    def __repr__(self):
        return '{}:{}'.format(self.__class__.__name__, self.name)

class Attacker(Host):
    def __init__(self):
        super(Attacker, self).__init__(name=self.__class__.__name__)

    def __getattr__(self, item):
        return self.__getattribute__(item)

    def flowup(self):
        pass

    def __repr__(self):
        return self.__class__.__name__

