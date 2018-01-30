import harmat as hm
from pyeda.inter import *
import sys
import time
import random
from itertools import tee


def pairwise(iterable):
    "s -> (s0,s1), (s1,s2), (s2, s3), ..."
    a, b = tee(iterable)
    next(b, None)
    return zip(a, b)


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


def path_converter(paths, key_func, order_edges=False):
    """
    converts paths to a boolean expression
    :param key_func: key function used to sort the paths
    :param order_edges: boolean to see if edges in paths are ordered
    :param paths: the list of all paths found by the attack graph
    :return: the boolean expression for edges of the paths and
     a dictionary for the probability associated with the edges
    """

    expr_string = ""
    expr_dict.clear()
    probability_dict = {}
    counter = 0
    num_edge = 0

    paths.sort(key=str)
    # build the dictionary of edges
    for path in paths:
        for i in range(1, len(path)):
            if (path[i - 1], path[i]) not in expr_dict:
                edge_name = "e{}".format(counter)
                expr_dict[(path[i - 1], path[i])] = [edge_name, 0]
                probability_dict[edge_name] = path[i].probability

                counter += 1
            expr_dict[(path[i - 1], path[i])][1] += 1

    # sort the paths
    if key_func is not None:
        paths.sort(key=key_func)

    for path in paths:
        # print(path)
        num_edge += len(path)
        # print(path)

        path_tuple = list(pairwise(path))
        # print(path_tuple)
        # sort edges
        if order_edges:
            path_tuple.sort(key=lambda x: expr_dict[x][1])
        for i in path_tuple:
            expr_string += expr_dict[i][0]
            if i != path_tuple[-1]:
                expr_string += "&"
        expr_string += "|"

    data_file.write("{},".format(num_edge))

    return expr_string[:-1], probability_dict


def pyeda(expression, probability_dict):
    # print(expression)
    # if expression == '':
    #     return

    start = time.time()
    f = expr(expression)
    f = expr2bdd(f)
    end = time.time()
    # print(expression)
    # print("construction time: ",end-start)
    data_file.write("{},".format(end - start))
    data_file.write("{},".format(expression))

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
    data_file.write("{},{},{}\n".format(end - start, length, sum))


def heuristic_test(key_func, order_edges):
    """
    tests the performance of the heuristic by generating random networks
    """

    # flag used to control the random network generated
    flag = True
    while flag:
        # initialise the harm
        h = hm.Harm()

        # create the top layer of the harm
        # top_layer refers to the top layer of the harm
        h.top_layer = hm.AttackGraph()

        # num_nodes=random.randint(10,15)
        num_nodes = 10
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
        if 200 > len(h.top_layer.all_paths) > 100:
            flag = False

    data_file.write("{},{},{},".format(num_nodes, density, len(h.top_layer.all_paths)))

    expr_string, probability_dict = path_converter(h.top_layer.all_paths, key_func, order_edges)
    pyeda(expr_string, probability_dict)


def edge_freq(path):
    total_freq = 0
    for i in range(1, len(path)):
        total_freq += expr_dict[(path[i - 1], path[i])][1]
    return total_freq


func_list = [(edge_freq, "edge frequency"), (lambda x: len(x), "length of path"), (None, "No order")]
expr_dict = {}
sort_edges = False
i = 2
data_file = open("heuristic_{}_{}_preprocess.csv".format(func_list[i][1], sort_edges), 'w')

# write header
data_file.write(
    "network size, density, num paths, num edge, construction time, paths, calculation time, num path in bdd,probability\n")

# data_file.write("\n")
# func_list = [None,None,None]
num_iter = 20
random.seed(123)
for j in range(num_iter):
    heuristic_test(func_list[i][0], sort_edges)
    print(j)
