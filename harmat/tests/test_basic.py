from harmat import *

def test_attack_tree():
    new_at = AttackTree()
    root_node = LogicGate("or")
    new_at.add_node(root_node)
    vul1 = Vulnerability("cve-1")
    vul1.risk = 2
    vul2 = Vulnerability("cve-2")
    vul2.risk = 3
    vul3 = Vulnerability("cve-3")
    vul3.risk = 5

    new_at.add_nodes_from([vul1, vul2, vul3])
    op = LogicGate("or")

    new_at.add_node(op)
    new_at.add_edge(root_node, vul1)
    new_at.add_edge(root_node, vul2)
    new_at.add_edge(root_node, op)
    new_at.add_edge(op, vul3)
    new_at.rootnode = root_node
    print(new_at.calculate_risk())

if __name__ == "__main__":
    testharm = Harm()

    testharm.load_json("../../examples/examplenet.json")

    target_name = "RouterEngineering"
    attacker_name = "Attacker"

    for node in testharm.top_layer.nodes():
        if node.name == target_name:
            target = node
        if node.name == attacker_name:
            attacker = node

    print("Metrics between {} and {}".format(attacker_name, target_name))
    print("Risk")
    print(testharm.top_layer.calculate_risk(attacker, target))
    print("Shortest path length")
    print(testharm.top_layer.calculate_shortest_path_length(attacker, target))
    print("SDPL")
    print(testharm.top_layer.calculate_SDPL(attacker, target))


