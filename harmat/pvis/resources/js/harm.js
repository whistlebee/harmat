function harm_upper(svg, width, height, json, charge, callback){
	add_boarder(svg, width, height, 0, 0, "steelblue", "black", 1.0, 5);
    var force = d3.layout.force()
        .size([width, height])
    	.charge(charge)
        .linkDistance(width/json.nodes.length)
        .on("tick", tick);
    var drag = force.drag()
    	.on("dragstart", dragstart);
	var link = svg.selectAll(".link")
	    .data(json.links)
	    .enter()
	    .append("line")
	    .attr("class", "link");
	var node = svg.selectAll(".node")
        .data(json.nodes)
        .enter()
        .append("g")
        .attr("class", "node")
        .call(force.drag);

	force
	    .nodes(json.nodes)
	    .links(json.links)
	    .start();
	
	node.append("circle")
        .attr("r", calc_radius)
        .style("fill", function(d) {return color_chooser(d);});
	
    node.append("text")
        .attr("dx", calc_radius)
        .attr("dy", ".35em")
        .text(function(d) {
        	if (d.name == "Attacker"){
        		return d.name;
        	}
        	else if (d.value > 0.7){
        		return d.name;
        	}})
        .style("fill", "white");
    
    node.append("title")
        .text(function(d) {
            return d.name + "\n" +
            	"Breach Probability: " + Math.round(d.value * 100) + "%";
        });
    
    node.on("dblclick", callback);
	
	function tick() {
        link.attr("x1", function(d) { return d.source.x; })
            .attr("y1", function(d) { return d.source.y; })
            .attr("x2", function(d) { return d.target.x; })
            .attr("y2", function(d) { return d.target.y; });
        node.attr("cx", function(d) {
    			var r = calc_radius(d);
                return d.x = Math.max(r, Math.min(width - r, d.x));
            })
	        .attr("cy", function(d) {
	        	var r = calc_radius(d);
	        	return d.y = Math.max(r, Math.min(height - r, d.y));
	        })
        	.attr("transform", function(d) {
        		return "translate(" + d.x + "," + d.y + ")"; 
        	});
	}

	function dragstart(d) {
		d3.select(this).classed("fixed", d.fixed = true);
	}
}

function harm_lower(svg, width, height, root, source) {
	add_boarder(svg, width, height, 0, 0, "steelblue", "black", 1.0, 5);
    var i = 0, duration = 750;
    var tree = d3.layout.tree()
	    .size([height, width]);
    var diagonal = d3.svg.diagonal()
	    .projection(function(d) { return [d.y, d.x]; });
    var shift = (width - getDepth(root) * 200) / 2;
    var nodes = tree.nodes(root).reverse();
    var links = tree.links(nodes);
    
    // Normalize for fixed-depth.
    nodes.forEach(function(d) { d.y = d.depth * 200 + shift; });
    // Update the nodes…
    var node = svg.selectAll("g.node")
        .data(nodes, function(d) { return d.id = ++i; });

    // Enter any new nodes at the parent's previous position.
    var nodeEnter = node.enter().append("g")
        .attr("class", "node")
        .attr("transform", function(d) {
                return "translate(" + source.y0 + "," + source.x0 + ")";});
        //.on("dblclick", click);
    
    nodeEnter.append("circle")
        .attr("r", 1e-6);

    nodeEnter.append("text")
        .attr("x",
            function(d) {
                return d.children || d._children ? 0 : calc_radius(d) + 2;
            })
        .attr("dy",
        	function(d) {
            	return d.children || d._children ? (-calc_radius(d) - 2) : 0;
        	})
        .attr("text-anchor",
            function(d) {
                return d.children || d._children ? "middle" : "start";
            })
        .text(function(d) { return d.name; })
        .style("fill-opacity", 1e-6)
        .style("fill", "white");
    
    nodeEnter.append("title")
        .text(function(d) {
            return "Breach Probability: " + Math.round(d.value * 100) + "%";
        });

    // Transition nodes to their new position.
    var nodeUpdate = node.transition()
        .duration(duration)
        .attr("transform",
            function(d) {
                return "translate(" + d.y + "," + d.x + ")";
            });

    nodeUpdate.select("circle")
        .attr("r", calc_radius)
        .style("fill", function(d) { return color_chooser(d); });

    nodeUpdate.select("text")
        .style("fill-opacity", 1);

    // Transition exiting nodes to the parent's new position.
    var nodeExit = node.exit().transition()
        .duration(duration)
        .attr("transform",
            function(d) {
                return "translate(" + source.y + "," + source.x + ")";
            })
        .remove();

    nodeExit.select("circle")
        .attr("r", 1e-6);

    nodeExit.select("text")
        .style("fill-opacity", 1e-6);

    // Update the links…
    var link = svg.selectAll("path.link")
        .data(links, function(d) { return d.target.id; });

    // Enter any new links at the parent's previous position.
    link.enter().insert("path", "g")
        .attr("class", "link")
        .attr("d", function(d) {
            var o = {x: source.x0, y: source.y0};
            return diagonal({source: o, target: o});
        });

    // Transition links to their new position.
    link.transition()
          .duration(duration)
          .attr("d", diagonal);

    // Transition exiting nodes to the parent's new position.
    link.exit().transition()
        .duration(duration)
        .attr("d", function(d) {
            var o = {x: source.x, y: source.y};
            return diagonal({source: o, target: o});
        })
        .remove();

    // Stash the old positions for transition.
    nodes.forEach(function(d) {
        d.x0 = d.x;
        d.y0 = d.y;
    });
    
    function click(d) {
        if (d.children) {
            d._children = d.children;
            d.children = null;
        } else {
            d.children = d._children;
            d._children = null;
        }
        harm_lower(svg, width, height, root, d);
    }
}

function getDepth(obj) {
    var depth = 0;
    if (obj.children) {
        obj.children.forEach(function (d) {
            var tmpDepth = getDepth(d);
            if (tmpDepth > depth) {
                depth = tmpDepth;
            }
        })
    }
    return 1 + depth;
}
