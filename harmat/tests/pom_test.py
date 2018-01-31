from itertools import product

from pomegranate import *

# The guests initial door selection is completely random

def table_generator(num_parent,prob):
    table=[]
    for i in product([True,False],repeat=num_parent+1):
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

# print(table_generator(3,0.9))

node0 = DiscreteDistribution( { True: 1,False:0 } )

node1=ConditionalProbabilityTable(
    table_generator(1,0.9),[node0]
)


node2=ConditionalProbabilityTable(
    table_generator(1,0.9),[node0]
)

node3=ConditionalProbabilityTable(
    table_generator(2,0.9),[node1,node2]
)



# State objects hold both the distribution, and a high level name.
s1 = State( node0, name="attacker" )
s2 = State( node1, name="host1" )
s3 = State( node2, name="host2" )
s4 = State( node3, name="target" )

# Create the Bayesian network object with a useful name
model = BayesianNetwork( "Bridge network" )

# Add the three states to the network
model.add_states(s1, s2, s3, s4)

# print(s4)
# print(s3)
# print(s2)
# print(s1)


# Add transitions which represent conditional dependencies, where the second node is conditionally dependent on the first node (Monty is dependent on both guest and prize)
model.add_transition(s1, s2)
model.add_transition(s1, s3)
# model.add_transition(s2, s3)
model.add_transition(s3, s4)
model.add_transition(s2, s4)
model.bake()

total=0
for a in [True, False]:
    for b in [True, False]:
        for c in [True, False]:
            for d in [True]:
                print([a,b,c,d])
                total+=model.probability([a,b,c,d])
                print(model.probability([a,b,c,d]))



print(total)