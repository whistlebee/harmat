import harmat as hm
import itertools
from pomegranate import *
from networkx import *
from pyeda.inter import *
vulnerability1 = hm.Vulnerability('CVE-0000', values={
    'risk': 10,
    'cost': 4,
    'probability': 0.9,
    'impact': 12
})

def path_converter(paths):
    """
    converts paths to a boolean expression
    :param paths: the list of all paths found by the attack graph
    :return: the boolean expression for edges of the paths and
     a dictionary for the probability associated with the edges
    """
    expr_string = ""
    expr_dict = {}
    probability_dict = {}
    counter = 0
    num_edge = 0

    for path in paths:
        for i in range(1, len(path)):
            if (path[i - 1], path[i]) not in expr_dict:
                edge_name = "e{}".format(counter)
                expr_dict[(path[i - 1], path[i])] = [edge_name,0]
                probability_dict[edge_name] = path[i].probability

                counter += 1
            expr_dict[(path[i - 1], path[i])][1]+=1


    def key_func(path):
        total_freq=0
        for i in range(1,len(path)):
            total_freq+=expr_dict[(path[i - 1], path[i])][1]
        return total_freq


    for path in sorted(paths,key=key_func):
        num_edge += len(path)
        for i in range(1, len(path)):
            expr_string += expr_dict[(path[i - 1], path[i])][0]
            if i != len(path) - 1:
                expr_string += "&"
        expr_string += "|"

    return expr_string[:-1], probability_dict


def pyeda(expression, probability_dict):

    f = expr(expression)
    f = expr2bdd(f)

    # print("construction time: ",end-start)

    sum = 0
    length = 0

    for i in f.satisfy_all():
        # print(i)
        prod = 1
        length += 1
        for key in i.keys():
            if i[key] == 0:
                prod *= 1 - probability_dict[str(key)]
            else:
                prod *= probability_dict[str(key)]
        sum += prod

    print("pyeda")
    print(sum)

    # print("calculation time: ", end-start)
    # print(f.to_dot())


def table_generator(num_parent,prob):
    table=[]
    for i in itertools.product([True,False],repeat=num_parent+1):
        row=list(i)
        if sum(row[:num_parent])==0:
            row.append(1-row[-1])
        else:
            if row[-1]:
                row.append(prob)
            else:
                row.append(1-prob)
        table.append(row)
    return table

def main():
    # initialise the harm
    h = hm.Harm()

    # create the top layer of the harm
    # top_layer refers to the top layer of the harm
    h.top_layer = hm.AttackGraph()

    num_nodes = 50
    density = random.uniform(0.3, 0.5)

    num_links = int(num_nodes * density)

    # we will create random nodes and connect them in some way
    # first we create some nodes
    hosts = [hm.Host("{}".format(i),{'discovered':False}) for i in range(num_nodes)]
    # then we will make a basic attack tree for each

    for host in hosts:
        # We specify the owner of the AttackTree so that the
        # AttackTree's values can be directly interfaced from the host
        host.lower_layer = hm.AttackTree(host=host)
        # We will make two vulnerabilities and give some metrics

        # basic_at creates just one OR gate and puts all vulnerabilities
        # the children nodes
        host.lower_layer.basic_at([vulnerability1])


    # random network
    for i in range(num_nodes):
        available_nodes = list(range(num_nodes))
        available_nodes.remove(i)
        for j in range(num_links):
            random_node = random.choice(available_nodes)
            h[0].add_edge(hosts[i], hosts[random_node])

            available_nodes.remove(random_node)
    #
    # h[0].add_edge(hosts[1], hosts[3])
    # h[0].add_edge(hosts[0], hosts[1])
    # h[0].add_edge(hosts[0], hosts[2])
    # h[0].add_edge(hosts[1], hosts[2])
    # h[0].add_edge(hosts[2], hosts[3])
    # h[0].add_edge(hosts[0], hosts[1])
    # h[0].add_edge(hosts[0], hosts[6])
    # h[0].add_edge(hosts[0], hosts[5])
    # h[0].add_edge(hosts[1], hosts[8])
    # h[0].add_edge(hosts[1], hosts[5])
    # h[0].add_edge(hosts[1], hosts[4])
    # h[0].add_edge(hosts[2], hosts[0])
    # h[0].add_edge(hosts[2], hosts[6])
    # h[0].add_edge(hosts[2], hosts[4])
    # h[0].add_edge(hosts[3], hosts[9])
    # h[0].add_edge(hosts[3], hosts[8])
    # h[0].add_edge(hosts[3], hosts[1])
    # h[0].add_edge(hosts[4], hosts[9])
    # h[0].add_edge(hosts[4], hosts[6])
    # h[0].add_edge(hosts[4], hosts[0])
    # h[0].add_edge(hosts[5], hosts[7])
    # h[0].add_edge(hosts[5], hosts[8])
    # h[0].add_edge(hosts[5], hosts[6])
    # h[0].add_edge(hosts[6], hosts[9])
    # h[0].add_edge(hosts[6], hosts[8])
    # h[0].add_edge(hosts[6], hosts[4])
    # h[0].add_edge(hosts[7], hosts[6])
    # h[0].add_edge(hosts[7], hosts[5])
    # h[0].add_edge(hosts[7], hosts[4])
    # h[0].add_edge(hosts[8], hosts[0])
    # h[0].add_edge(hosts[8], hosts[3])
    # h[0].add_edge(hosts[8], hosts[7])
    # h[0].add_edge(hosts[9], hosts[1])
    # h[0].add_edge(hosts[9], hosts[8])
    # h[0].add_edge(hosts[9], hosts[6])


    # Now we set the attacker and target
    h[0].source = hosts[0]
    h[0].target = hosts[num_nodes-1]

    # do some flow up
    h.flowup()

    make_DAG(h.top_layer)

    generate_bayesian(h.top_layer)


def bayes_net(G,conditional_dict,current_node):
    """recursively back propagate through nodes"""
    if current_node in conditional_dict.keys():
        return

    if current_node==G.source:
        conditional_dict[current_node] = DiscreteDistribution({True:1,False:0})

        return

    if list(G.predecessors_iter(current_node))==[]:
        conditional_dict[current_node]=DiscreteDistribution({True:current_node.probability,False:1-current_node.probability})

        return

    parent_list = []
    for parent in G.predecessors_iter(current_node):
        bayes_net(G,conditional_dict,parent)
        parent_list.append(conditional_dict[parent])

    conditional_dict[current_node]=ConditionalProbabilityTable(
        table_generator(len(parent_list), current_node.probability), parent_list)



def generate_bayesian(G):
    """
    generates the bayesian network with pomegranate
    :param G: attack graph
    :return:
    """
    conditional_dict={}
    state_dict={}
    # print(list(G.edges()))
    # return
    bayes_net(G,conditional_dict,G.target)



    model=BayesianNetwork("B-Harm")
    host_list=[]
    counter=0
    for node in conditional_dict.keys():
        state_dict[node]=State(conditional_dict[node],name=str(node))
        if node==G.target:
            target_index=counter
        model.add_state(state_dict[node])
        host_list.append(node)
        counter+=1


    for edge in G.edges():
        try:
            model.add_transition(state_dict[edge[0]],
                                state_dict[edge[1]])
        except KeyError as e:
            continue

    model.bake()
    total=0
    risk=0
    roa=0
    total_ac=0

    for i in itertools.product([True, False], repeat=len(state_dict.keys())-1):
        scenario=list(i)
        scenario.insert(target_index,True)

        probability = model.probability(scenario)
        if probability <= 1e-4:
            continue

        total_impact=0
        attack_cost=0
        total_roa=0
        for i in range(len(scenario)):
            if scenario[i]==True:

                total_impact+=host_list[i].impact
                attack_cost+=host_list[i].cost
                total_roa+=host_list[i].impact/host_list[i].cost

        total_ac+=probability*attack_cost
        total+=probability
        risk+=probability*total_impact
        roa+=probability*total_roa

    print("probability",total)
    print("risk",risk)
    print("ROA",roa)
    print("attack cost",total_ac)


def visit(G, v, host_dict, prev_node=None):
    if host_dict[v]=='permanent':
        return
    if host_dict[v]=='temporary':
        G.remove_edge(prev_node,v)
        return

    host_dict[v]='temporary'

    for nbr in G.neighbors(v):
        visit(G, nbr, host_dict, v)

    host_dict[v]='permanent'




def make_DAG(G):
    """
    returns a dictionary with parents of all nodes
    """
    host_dict={u:'unmarked' for u in list(G.hosts())}

    while 'unmarked' in host_dict.values():
        for i in host_dict.keys():
            if host_dict[i]=='unmarked':
                visit(G, i, host_dict)


def enterprise_network():
    Total_Num_node1 = 1
    enterprise = hm.Harm()

    # create the top layer of the harm
    enterprise.top_layer = hm.AttackGraph()

    A = hm.Attacker()  # attacker
    WS1 = hm.Host("WS1")
    WS2 = hm.Host("WS2")
    AS1 = hm.Host("AS1")
    AS2 = hm.Host("AS2")
    DB3 = hm.Host("DB3")
    # create some nodes
    # target


    # then we will make a basic attack tree for host
    WS1.lower_layer = hm.AttackTree()
    WS2.lower_layer = hm.AttackTree()
    AS1.lower_layer = hm.AttackTree()
    AS2.lower_layer = hm.AttackTree()
    DB3.lower_layer = hm.AttackTree()


    # WS1
    vul1 = hm.Vulnerability("CVE-2015-3185", values={'risk': 4.3, 'cost': 5.7, 'probability': 0.43, 'exploitability': 0.55, 'impact': 5.5,'defense_cost': 15})
    vulw1 = hm.Vulnerability("CVE-2015-5700",values={'risk': 2.1, 'cost': 7.9, 'probability': 0.21, 'exploitability': 0.29, 'impact': 2.9, 'defense_cost': 15})

    #WS2
    vulw2 = hm.Vulnerability("CVE-2015-3185",values={'risk': 4.3, 'cost': 5.7, 'probability': 0.43, 'exploitability': 0.55, 'impact': 5.5,'defense_cost': 15})
    vulw22 = hm.Vulnerability("CVE-2015-5700",values={'risk': 2.1, 'cost': 7.9, 'probability': 0.21, 'exploitability': 0.29, 'impact': 2.9, 'defense_cost': 15})

    # AS1
    vul2 = hm.Vulnerability("CVE-2015-0900",values={'risk': 4.3, 'cost': 5.7, 'probability': 0.43, 'exploitability': 0.55, 'impact': 5.5,'defense_cost': 18})
    vulas1 = hm.Vulnerability("CVE-2013-0638", values={'risk': 10.0, 'cost': 0.1, 'probability': 1.0, 'exploitability': 0.64,'impact': 6.4, 'defense_cost': 18})

    # AS2
    vul0 = hm.Vulnerability("CVE-2016-0763",values={'risk': 4.3, 'cost': 5.7, 'probability': 0.43, 'exploitability': 0.64, 'impact': 6.4,'defense_cost': 18})
    vulas2  = hm.Vulnerability("CVE-2015-0900",values={'risk': 4.3, 'cost': 5.7, 'probability': 0.43, 'exploitability': 0.55, 'impact': 5.5,'defense_cost': 18})

    # DB3
    vul5 = hm.Vulnerability("CVE-2012-1675",values={'risk': 7.5, 'cost': 2.5, 'probability': 0.75, 'exploitability': 0.64, 'impact': 6.4, 'defense_cost': 20})
    vuldb3 = hm.Vulnerability("CVE-2015-0900",values={'risk': 4.3, 'cost': 5.7, 'probability': 0.43, 'exploitability': 0.55, 'impact': 5.5,'defense_cost': 20})

    # universal - such that there is always an attack path
    universal = hm.Vulnerability("CVE", values={'risk': 0.1, 'cost': 9.9, 'probability': 0.01, 'exploitability': 0.01, 'impact': 0.1, 'defense_cost': 0})

    # add vulnerabilities to host nodes
    WS1.lower_layer.basic_at([vul1, vulw1, universal])


    WS2.lower_layer.basic_at([vulw2, vulw22])
    AS1.lower_layer.basic_at([vul2, vulas1, universal])
    AS2.lower_layer.basic_at([vul0, vulas2])
    DB3.lower_layer.basic_at([vul5, vuldb3])
    # add edges for servers
    enterprise[0].add_edge_between(A, [WS1, WS2])
    enterprise[0].add_edge_between(WS1, [AS1, AS2])
    enterprise[0].add_edge_between(WS2, [AS1, AS2])
    enterprise[0].add_edge_between(AS1, DB3)
    enterprise[0].add_edge_between(AS2, DB3)

    # '''
    # For Workstations
    #Host('h' + str(n + 1))
    hosts = [hm.Host('h' + str(i + 1)) for i in range(Total_Num_node1)]
    for host in hosts:
        host.lower_layer = hm.AttackTree()
        vulH0 = hm.Vulnerability("CVE-2014-5270", values={'risk': 2.1,'cost': 7.9,'probability': 0.21,'exploitability': 0.2,'impact': 2,'defense_cost':10})
        vulH1 = hm.Vulnerability("CVE-2016-2834",values={'risk': 8.8, 'cost': 1.2, 'probability': 0.88, 'exploitability': 1.0,'impact': 10, 'defense_cost': 10})

        # add vulnerabilities to host nodes
        host.lower_layer.basic_at([vulH0, vulH1])


        # Asset value for workstations
        host.values['asset_value'] = 50
        host.values['exposure_factor'] = 0.06


        # connection between web severs/app servers to user workstations
    for u in hosts :
        enterprise[0].add_edge_between(WS1, u)
        enterprise[0].add_edge_between(WS2, u)
        enterprise[0].add_edge_between(u, AS1)
        enterprise[0].add_edge_between(u, AS2)

    return enterprise


def simulation():
    tharm = enterprise_network()

    source = ""
    target = ""
    for host in tharm.top_layer.nodes():
        if host.name == "Attacker":
            source = host
        if host.name == "DB3":
            target = host
    tharm[0].source = source
    tharm[0].target = target

    tharm.flowup()
    hm.HarmSummary(tharm).show()
    print("Probability Attack Success\t\t     {:3.4f}".format(tharm[0].probability_attack_success()))

    generate_bayesian(tharm.top_layer)



    tharm.top_layer.find_paths()
    expr_string, probability_dict = path_converter(tharm.top_layer.all_paths)
    pyeda(expr_string, probability_dict)


"""
------------------------------------------------------------------------------------------
Part: RUN SIMULATION
------------------------------------------------------------------------------------------
"""

main()