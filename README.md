# Hierarchical Attack Representation Model Analysis Tool

Harmat is an engine for HARM (Hierarchical Attack Representation Model) analysis.
Currently work-in-progress.

To install:

`python setup.py`

Or alternatively (if you want to install as a symlink):

`python setup.py develop`

---

### Environment Setup ###
* CentOS:
*   yum install python-virtualenv
*   if not using virtualenv:
*       rpm -ivh http://dl.fedoraproject.org/pub/epel/6/i386/epel-release-6-8.noarch.rpm
*       yum install python-pip
* cd safeview
* virtualenv env
* source env/bin/activate

### Dependencies ###
* Follow tiscovery README.md
* Follow harmat README.md
* pip install networkx tabulate statistics future
* cd harmat
* python setup.py develop

## Use examples

### Simple example
As an example, we will generate a random harm and calculate some metrics on it

```{python}
import harmat as hm

h = hm.generate_random_harm(node_count=15,vul_count=1, edge_prob=0.3)
h.flowup()
hm.HarmSummary(h).show()
```

The function `generate_random_harm` generates a random harm using the Erdos-Renyi random graph generation algorithm. 
Alternatively, the `graph_function` argument can be specified for a different graph generation algorithm. `.flowup()` is a function in most models within the HARM. It allows metrics to "flow up" from the vulnerabilities to the higher layer nodes.
`HarmSummary` is a class which you can decide what metrics you want calculated.

### Little more detailed example

In this example, we will manually create a HARM by hand.

```{python}
import harmat as hm

if __name__ == "__main__":
    # initialise the harm
    h = hm.Harm()

    # create the top layer of the harm
    # top_layer refers to the top layer of the harm
    h.top_layer = hm.AttackGraph()

    # we will create 5 nodes and connect them in some way
    # first we create some nodes
    hosts = [hm.Host("Host {}".format(i)) for i in range(5)]
    # then we will make a basic attack tree for each
    for host in hosts:
        host.lower_layer = hm.AttackTree()
        # We will make two vulnerabilities and give some metrics
        vulnerability1 = hm.Vulnerability('CVE-0000', values = {
            'risk' : 10,
            'cost' : 4,
            'probability' : 0.5,
            'impact' : 12
        })
        vulnerability2 = hm.Vulnerability('CVE-0001', values = {
            'risk' : 1,
            'cost' : 5,
            'probability' : 0.2,
            'impact' : 2
        })
        # basic_at creates just one OR gate and puts all vulnerabilites
        # the children nodes
        host.lower_layer.basic_at([vulnerability1, vulnerability2])
    # To add edges we simply use the add_edge function
    # here h[0] refers to the top layer
    h[0].add_edge(hosts[0], hosts[3])
    h[0].add_edge(hosts[1], hosts[0])
    h[0].add_edge(hosts[0], hosts[2])
    h[0].add_edge(hosts[3], hosts[4])
    h[0].add_edge(hosts[3], hosts[2])

    # Now we set the attacker and target
    h[0].source = hosts[0]
    h[0].target = hosts[4]

    # do some flow up
    h.flowup()

    # Now we will run some metrics
    hm.HarmSummary(h).show()
```

## Developing for Harmat

Metrics are implemented within each model. i.e. Harm, Attack Graph, Attack Tree.
Some things to know:
* AG is a subclass of the NetworkX.DiGraph class.
* Every node has a values dictionary which is used to store all necessary properties of the node.
* Try to write your own Summary class to make analysis simpler. 
* Many things may not be implemented.
Note that metrics may already be implemented in NetworkX so I recommend looking through the NetworkX documentation beforehand.



