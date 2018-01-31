import harmat as hm
from pyeda.inter import *
import sys
import time
import random

vulnerability1 = hm.Vulnerability('CVE-0000', values={
    'risk': 10,
    'cost': 4,
    'probability': 0.5,
    'impact': 12
})
vulnerability2 = hm.Vulnerability('CVE-0001', values={
    'risk': 1,
    'cost': 5,
    'probability': 0.2,
    'impact': 2
})

vulnerability3 = hm.Vulnerability('CVE-0001', values={
    'risk': 1,
    'cost': 5,
    'probability': 0.75,
    'impact': 2
})

data_file = open("data.csv", 'a')
# write header
# data_file.write("network size, density, num paths, num edge, construction time, calculation time, num path in bdd \n")
data_file.write("\n")


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
    data_file.write("{},".format(num_edge))
    return expr_string[:-1], probability_dict


def pyeda(expression, probability_dict):

    start = time.time()
    f = expr(expression)
    f = expr2bdd(f)
    end = time.time()
    # print("construction time: ",end-start)
    data_file.write("{},".format(end - start))

    sum = 0
    length = 0
    start = time.time()
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
    # print(sum)
    end = time.time()
    # print("calculation time: ", end-start)
    # print(f.to_dot())
    data_file.write("{},{}\n".format(end - start, length))


def performance_test():
    """
    tests the performance of the algorithm by generating random networks
    """

    # flag used to control the random network generated
    flag = True
    while (flag):
        # initialise the harm
        h = hm.Harm()

        # create the top layer of the harm
        # top_layer refers to the top layer of the harm
        h.top_layer = hm.AttackGraph()

        # num_nodes = random.randint(10, 15)
        num_nodes=10
        density = random.uniform(0.3, 0.5)

        num_links = int(num_nodes * density)
        # print("network size: ",num_nodes)
        # print("network density: ",density)

        # we will create random nodes and connect them in some way
        # first we create some nodes
        hosts = [hm.Host("{}".format(i)) for i in range(num_nodes)]
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

        # Now we set the attacker and target
        h[0].source = hosts[0]
        h[0].target = hosts[num_nodes - 1]

        # do some flow up
        h.flowup()

        h.top_layer.find_paths()

        # print("number of paths: ",len(h.top_layer.all_paths))
        if len(h.top_layer.all_paths) < 300 and len(h.top_layer.all_paths) > 0:
            flag = False

    data_file.write("{},{},{},".format(num_nodes, density, len(h.top_layer.all_paths)))
    expr_string, probability_dict = path_converter(h.top_layer.all_paths)
    pyeda(expr_string, probability_dict)


    # Now we will run some metrics
    # print(h[0].probability_attack_success())


num_test = 2
for i in range(num_test):
    random.seed(0)
    performance_test()
    print(float(i) / num_test)
