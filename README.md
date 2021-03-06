# Hierarchical Attack Representation Model Analysis Tool

Harmat is an engine for HARM (Hierarchical Attack Representation Model) analysis used in the Safelite project. It is written using Cython with the Boost Graph Library for speed. However, the API closely follows NetworkX to the point that you can use NetworkX functions directly.

## Installation

### Building from source

__Compilation requires a C++14 compatible compiler.__

#### Linux

Install Boost C++ through your package manager.

```console
$ git clone https://github.com/whistlebee/harmat
$ cd harmat
$ python setup.py install
```


#### macOS

```console
$ brew install boost
$ git clone https://github.com/whistlebee/harmat
$ cd harmat
$ export MACOSX_DEPLOYMENT_TARGET=10.9
$ python setup.py install
```

#### Windows

Download and install [Boost](https://www.boost.org/users/download/).

Install Visual C++ Build tools.


```console
git clone https://github.com/whistlebee/harmat
cd harmat
python setup.py install
```



#### Optional

Install `pomegranate` with `--no-deps` flag to use Bayesian Harm features.

```console
$ pip install git+https://github.com/jmschrei/pomegranate.git --no-deps"
```

Package dependencies
* `numpy`
* `scipy`
* `joblib`
* `pyyaml`

---

## Usage examples

In this example, we will manually create a HARM by hand.

```python
import harmat as hm

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
    
# Now we will create an Attacker. This is not a physical node but it exists to describe
# the potential entry points of attackers.
attacker = hm.Attacker() 

# To add edges we simply use the add_edge function
# here h[0] refers to the top layer
# add_edge(A,B) creates a uni-directional from A -> B.
h[0].add_edge(attacker, hosts[0]) 
h[0].add_edge(hosts[0], hosts[3])
h[0].add_edge(hosts[1], hosts[0])
h[0].add_edge(hosts[0], hosts[2])
h[0].add_edge(hosts[3], hosts[4])
h[0].add_edge(hosts[3], hosts[2])


# Now we set the attacker and target
h[0].source = attacker
h[0].target = hosts[4]

# do some flow up
h.flowup()

# Now we will run some metrics
hm.HarmSummary(h).show()
```

## Some things to know

* harmat.AttackGraph compatible with the NetworkX.DiGraph class. This allows us to take advantage of networkX's functionalities.
* Every node has a `values` dictionary which is used to store all necessary properties of the node.
For example:
 
```python
import harmat as hm
     
# Cleanest way
vul_a = hm.Vulnerability('TestingVul_A', values={'risk': 10}) 
     
# This is identical to:
vul_b = hm.Vulnerability('TestingVul_B')
vul_b.risk = 10
```
* There is a built-in `HarmSummary` class to make formatting of analysis easier.
* The API constantly changing by making new features
which means updating to newer versions may break your code.

---
## Some features

### Flowup

In an Attack Tree, we must calculate the each node's values from the leaves (Vulnerabilities) all the way up to the
root node. This can easily achieved using the `.flowup()` method available `Harm`, `AttackGraph`, `Host` and `AttackTree`
classes. 

The actual calculation strategy is defined as a class variable of `AttackTree`. As follows:
```python
flowup_calc_dict = OrderedDict({
    'or': OrderedDict({
        'risk': flowup_max,
        'cost': flowup_min,
        'impact': flowup_max,
        'probability': flowup_or_prob
    }),
    'and': OrderedDict({
        'risk': flowup_sum,
        'cost': flowup_sum,
        'impact': flowup_sum,
        'probability': flowup_and_prob
    }),
})
```
You can easily remove some metrics you don't need, add new metrics easily by modifying this.

### Ignorables

In some cases, we may want to ignore all calculations on some nodes. This is possible when we assume that network devices
such as switches and routers are not required to be breached.

In harmat:
```python
# h is an existing harm
# '192.168.1.254' is the host name of the router we want to ignore.

router = h[0].find_node('192.168.1.254')
router.ignorable = True

# Now, the router will always allow the path finding to go through it and not exist in any attack paths.
# Sometimes you may want to filter out ignorables with some iterators.
hosts = list(h[0].hosts())
filtered_hosts = hm.filter_ignorables(hosts)
```
