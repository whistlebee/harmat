//
//  harmatbgl.h
//  harmatbgl provides an interface around Boost Graph Library's Adjacency list.
//  Additional functions are use for easier interfacing within Python
//

#ifndef harmat_bgl_h
#define harmat_bgl_h

#include <iostream>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/graph_traits.hpp>
#include <boost/graph/graph_utility.hpp>
#include <boost/graph/transpose_graph.hpp>
#include <cstdint>
#include <iterator>

namespace harmat
{

template <typename NodeProperty>
class Graph
{
  public:
    using BoostAdjacencyList = typename boost::adjacency_list<
        boost::setS,            // OutEdgeList
        boost::listS,           // VertexList
        boost::bidirectionalS,  // Directed
        NodeProperty *,         // VertexProperties
        boost::no_property,     // EdgeProperties
        boost::no_property,     // GraphProperties
        boost::listS            // EdgeList
    >;
    using adjacency_iterator = typename boost::graph_traits<BoostAdjacencyList>::adjacency_iterator;
    using in_edge_iterator = typename boost::graph_traits<BoostAdjacencyList>::in_edge_iterator;
    using out_edge_iterator = typename boost::graph_traits<BoostAdjacencyList>::out_edge_iterator;
    using edge_iterator = typename boost::graph_traits<BoostAdjacencyList>::edge_iterator;
    using vertex_descriptor = typename boost::graph_traits<BoostAdjacencyList>::vertex_descriptor;
    using vertex_iterator = typename BoostAdjacencyList::vertex_iterator;
    using descriptor_map = typename std::unordered_map<NodeProperty *, vertex_descriptor>;
    Graph() = default;

    Graph(BoostAdjacencyList graph, descriptor_map map) {
        internal_g = graph;
        desc_map = map;
    }

    uint32_t num_vertices()
    {
        return static_cast<uint32_t>(boost::num_vertices(internal_g));
    }

    Graph<NodeProperty>* reverse() {
        auto g = new Graph();
        for (auto vd: boost::make_iterator_range(boost::vertices(internal_g))) {
            auto vd2 = boost::add_vertex(g->internal_g);
            NodeProperty* np = internal_g[vd];
            g->internal_g[vd2] = np;
            g->desc_map[np] = vd2;
        }
        edge_iterator ei, ei_end;
        for (boost::tie(ei, ei_end) = boost::edges(internal_g); ei != ei_end; ++ei)
        {
            auto source = boost::source(*ei, internal_g);
            auto target = boost::target(*ei, internal_g);
            auto source_np = g->internal_g[source];
            auto target_np = g->internal_g[target];
            boost::add_edge(g->desc_map[target_np], g->desc_map[source_np], g->internal_g);
        }
        return g;
    }

    void add_edge(NodeProperty *np1, NodeProperty *np2)
    {
        boost::add_edge(desc_map[np1], desc_map[np2], internal_g);
    }

    void add_vertex(NodeProperty *np)
    {
        vertex_descriptor vd = boost::add_vertex(internal_g);
        if (vd != nullptr)
        {
            internal_g[vd] = np;
            desc_map[np] = vd;
        }
    }

    void remove_vertex(NodeProperty *np)
    {
        vertex_descriptor vd = desc_map[np];
        if (vd != nullptr) {
            boost::clear_vertex(vd, internal_g);
            boost::remove_vertex(vd, internal_g);
            desc_map.erase(np);
        }
    }

    void remove_edge(NodeProperty *np1, NodeProperty *np2)
    {
        auto vd1 = desc_map[np1];
        auto vd2 = desc_map[np2];
        boost::remove_edge(vd1, vd2, internal_g);
    }

    std::vector<NodeProperty *> nodes()
    {
        auto node_vec = std::vector<NodeProperty *>();
        for (auto vd: boost::make_iterator_range(boost::vertices(internal_g))) {
            node_vec.push_back(internal_g[vd]);
        }
        return node_vec;
    }

    std::vector<NodeProperty *> in_nodes(NodeProperty *node)
    {
        auto node_vec = std::vector<NodeProperty *>();
        in_edge_iterator ei, ei_end;
        vertex_descriptor vd = desc_map[node];
        if (vd == nullptr)
            return node_vec;
        for (boost::tie(ei, ei_end) = boost::in_edges(vd, internal_g); ei != ei_end; ++ei)
        {
            auto source = boost::source(*ei, internal_g);
            node_vec.push_back(internal_g[source]);
        }
        return node_vec;
    }

    std::vector<NodeProperty *> out_nodes(NodeProperty *node)
    {
        auto node_vec = std::vector<NodeProperty *>();
        out_edge_iterator ei, ei_end;
        vertex_descriptor vd = desc_map[node];
        if (vd == nullptr)
            return node_vec;
        for (boost::tie(ei, ei_end) = boost::out_edges(vd, internal_g); ei != ei_end; ++ei)
        {
            auto source = boost::target(*ei, internal_g);
            node_vec.push_back(internal_g[source]);
        }
        return node_vec;
    }

    std::vector<std::pair<NodeProperty *, NodeProperty *>> out_edges(NodeProperty *node)
    {
        auto edges = std::vector<std::pair<NodeProperty *, NodeProperty *>>();
        in_edge_iterator ei, ei_end;
        vertex_descriptor vd = desc_map[node];
        if (vd == nullptr)
            return edges;
        for (boost::tie(ei, ei_end) = boost::out_edges(vd, internal_g); ei != ei_end; ++ei)
        {
            auto source = boost::source(*ei, internal_g);
            auto target = boost::target(*ei, internal_g);
            auto pair = std::pair<NodeProperty *, NodeProperty *>(internal_g[source], internal_g[target]);
            edges.push_back(pair);
        }
        return edges;
    }

    std::vector<std::pair<NodeProperty *, NodeProperty *>> in_edges(NodeProperty *node)
    {
        auto edges = std::vector<std::pair<NodeProperty *, NodeProperty *>>();
        in_edge_iterator ei, ei_end;
        vertex_descriptor vd = desc_map[node];
        if (vd == nullptr)
            return edges;
        for (boost::tie(ei, ei_end) = boost::in_edges(vd, internal_g); ei != ei_end; ++ei)
        {
            auto source = boost::source(*ei, internal_g);
            auto target = boost::target(*ei, internal_g);
            auto pair = std::pair<NodeProperty *, NodeProperty *>(internal_g[source], internal_g[target]);
            edges.push_back(pair);
        }
        return edges;
    }

    std::vector<std::pair<NodeProperty *, NodeProperty *>> edges()
    {
        auto edges = std::vector<std::pair<NodeProperty *, NodeProperty *>>();
        edge_iterator ei, ei_end;
        for (boost::tie(ei, ei_end) = boost::edges(internal_g); ei != ei_end; ++ei)
        {
            auto source = boost::source(*ei, internal_g);
            auto target = boost::target(*ei, internal_g);
            auto pair = std::pair<NodeProperty *, NodeProperty *>(internal_g[source], internal_g[target]);
            edges.push_back(pair);
        }
        return edges;
    }

    std::pair<adjacency_iterator, adjacency_iterator> adjacent_vertices(vertex_descriptor vd)
    {
        return boost::adjacent_vertices(vd, internal_g);
    }

    vertex_descriptor to_vd(NodeProperty* np)
    {
        return desc_map[np];
    }

    NodeProperty* to_np(vertex_descriptor vd)
    {
        return internal_g[vd];
    }

  private:
    descriptor_map desc_map;
    BoostAdjacencyList internal_g;
};
}

#endif /* harmat_bgl_h */
