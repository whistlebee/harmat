import harmat
from flask import Flask, render_template, Response

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/data')
def data():
    h = harmat.vis.visualisation.generate_random_harm(100, 5, edge_prob=0.01)
    h.top_layer.initialise_vis_metrics()
    et = harmat.vis.xmlify(h)
    xmlstr = harmat.vis.et_to_string(et.getroot())
    return Response(response=xmlstr, status=200, mimetype="application/xml")


#h = harmat.generate_random_harm(20, 10)

if __name__ == "__main__":
    app.debug = True
    app.run()
