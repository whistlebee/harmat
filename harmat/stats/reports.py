from harmat import *
import networkx as nx
from jinja2 import Template
import plotly.plotly as py
import plotly.graph_objs as go
import plotly.tools as tls
from flask import Flask, render_template
app = Flask(__name__)
import os
import sys

sys.path.append('~/Desktop/misc/safelite_test/')

random_harm = harmat.generate_random_harm(20, 5, edge_prob=0.15)
random_harm.top_layer.initialise_vis_metrics()

@app.route("/")
def template_test():
    num_nodes = nx.number_of_nodes(random_harm.top_layer)
    num_edges = nx.number_of_edges(random_harm.top_layer)
    highest_risk = max([node.lower_layer.rootnode.risk for node in random_harm.top_layer.nodes()])
    nodes = random_harm.top_layer.nodes()
    source, target = nodes[0], nodes[1]
    risk = random_harm.top_layer.calculate_risk(source, target)
    #roa = random_harm.top_layer.calculate_return_on_attack(source, target)
    mopl = random_harm.top_layer.calculate_MoPL(source, target)
    mpl = random_harm.top_layer.calculate_MPL(source, target)
    sdpl = random_harm.top_layer.calculate_SDPL(source, target)
    sp = random_harm.top_layer.calculate_shortest_path_length(source, target)


    return render_template('index.html', num_nodes=num_nodes, num_edges=num_edges,
                           highest_risk=highest_risk, source=source.name,
                           target=target.name, risk=risk, roa=None, mopl=mopl, mpl=mpl,
                           sdpl=sdpl, sp=sp)

@app.route("/reset")
def reset():
    random_harm = harmat.generate_random_harm(10, 5, edge_prob=0.2)
    random_harm.top_layer.initialise_vis_metrics()

@app.route("/data")
def data():
    et = harmat.vis.xmlify(random_harm)
    xmlstr = harmat.vis.et_to_string(et.getroot())
    return Response(response=xmlstr, status=200, mimetype="application/xml")

if __name__ == '__main__':
    app.run(debug=True)