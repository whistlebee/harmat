//
//  harmatbgl.h
//  harmatbgl
//

#ifndef harmat_bgl_h
#define harmat_bgl_h

#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/graph_traits.hpp>
#include <cstdint>
#include <iterator>

namespace harmat
{

template <typename NodeProperty>
class Graph
{
    using BoostAdjacencyList = typename boost::adjacency_list<
        boost::hash_setS,       // OutEdgeList
        boost::hash_setS,           // VertexList
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
    using vertex_descriptor = typename BoostAdjacencyList::vertex_descriptor;

  public:
    Graph() : internal_g(BoostAdjacencyList()) {}

    uint32_t num_vertices()
    {
        return static_cast<uint32_t>(boost::num_vertices(internal_g));
    }

    void add_edge(NodeProperty *np1, NodeProperty *np2)
    {
        boost::add_edge(descriptor_map[np1], descriptor_map[np2], internal_g);
    }

    void add_vertex(NodeProperty *np)
    {
        vertex_descriptor vd = boost::add_vertex(internal_g);
        if (vd != nullptr)
        {
            internal_g[vd] = np;
            descriptor_map[np] = vd;
        }
    }

    void remove_vertex(NodeProperty *np)
    {
        vertex_descriptor vd = descriptor_map[np];
        if (vd != nullptr) {
            boost::clear_vertex(vd, internal_g);
            boost::remove_vertex(vd, internal_g);
            descriptor_map.erase(np);
        }
    }

    std::vector<NodeProperty *> nodes()
    {
        typename boost::graph_traits<BoostAdjacencyList>::vertex_iterator vertexIt, vertexEnd;
        std::tie(vertexIt, vertexEnd) = boost::vertices(internal_g);
        std::vector<NodeProperty *> node_vec = std::vector<NodeProperty *>();
        for (; vertexIt != vertexEnd; ++vertexIt)
            node_vec.push_back(internal_g[*vertexIt]);
        return node_vec;
    }

    std::vector<NodeProperty *> in_nodes(NodeProperty *node)
    {

        std::vector<NodeProperty *> node_vec = std::vector<NodeProperty *>();
        in_edge_iterator ei, ei_end;
        vertex_descriptor vd = descriptor_map[node];
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
        std::vector<NodeProperty *> node_vec = std::vector<NodeProperty *>();
        out_edge_iterator ei, ei_end;
        vertex_descriptor vd = descriptor_map[node];
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
        std::vector<std::pair<NodeProperty *, NodeProperty *>> edges = std::vector<std::pair<NodeProperty *, NodeProperty *>>();
        in_edge_iterator ei, ei_end;
        vertex_descriptor vd = descriptor_map[node];
        if (vd == nullptr)
            return edges;
        for (boost::tie(ei, ei_end) = boost::out_edges(vd, internal_g); ei != ei_end; ++ei)
        {
            auto source = boost::source(*ei, internal_g);
            auto target = boost::target(*ei, internal_g);
            std::pair<NodeProperty *, NodeProperty *> pair = std::pair<NodeProperty *, NodeProperty *>(internal_g[source], internal_g[target]);
            edges.push_back(pair);
        }
        return edges;
    }

    std::vector<std::pair<NodeProperty *, NodeProperty *>> in_edges(NodeProperty *node)
    {
        std::vector<std::pair<NodeProperty *, NodeProperty *>> edges = std::vector<std::pair<NodeProperty *, NodeProperty *>>();
        in_edge_iterator ei, ei_end;
        vertex_descriptor vd = descriptor_map[node];
        if (vd == nullptr)
            return edges;
        for (boost::tie(ei, ei_end) = boost::in_edges(vd, internal_g); ei != ei_end; ++ei)
        {
            auto source = boost::source(*ei, internal_g);
            auto target = boost::target(*ei, internal_g);
            std::pair<NodeProperty *, NodeProperty *> pair = std::pair<NodeProperty *, NodeProperty *>(internal_g[source], internal_g[target]);
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
            std::pair<NodeProperty *, NodeProperty *> pair = std::pair<NodeProperty *, NodeProperty *>(internal_g[source], internal_g[target]);
            edges.push_back(pair);
        }
        return edges;
    }

  private:
    std::unordered_map<NodeProperty *, vertex_descriptor> descriptor_map;
    BoostAdjacencyList internal_g;
};
}

#endif /* harmat_bgl_h */
