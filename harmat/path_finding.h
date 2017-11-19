#ifndef harmat_path_finding_h
#define harmat_path_finding_h

#include <vector>
#include <unordered_set>
#include <set>
#include <algorithm>
#include <boost/container/static_vector.hpp>
#include "bglgraph.h"


namespace harmat
{

template <typename T>
bool inline vulnerable_or_ignorable(T* np)
{
    return (np->probability != 0) or np->ignorable;
}

template <typename T>
std::vector<std::vector<T*>> ag_all_simple_attack_paths(
    Graph<T>& G,
    T* source,
    T* target)
{
    typedef typename Graph<T>::vertex_descriptor vertd;
    typedef typename Graph<T>::adjacency_iterator adjacency_iterator;

    const unsigned int num_nodes = G.num_vertices();

    vertd vd_target = G.to_vd(target);
    vertd vd_source = G.to_vd(source);

    std::vector<std::pair<adjacency_iterator, adjacency_iterator>> stack;
    std::vector<std::vector<vertd>> paths;
    std::unordered_set<vertd> traversed;
    std::vector<vertd> visited;
    adjacency_iterator *ai, *ai_end;
    std::vector<std::vector<T*>> finals;

    stack.reserve(num_nodes);
    visited.reserve(num_nodes);

    if (num_nodes < 2)
        return finals;

    const unsigned int cutoff = num_nodes - 1;


    traversed.reserve(num_nodes);
    visited.push_back(vd_source);
    traversed.insert(vd_source);
    stack.emplace_back(G.adjacent_vertices(vd_source));
    while (!stack.empty())
    {
        ai = &stack.back().first;
        ai_end = &stack.back().second;
        if (*ai == *ai_end)
        {
            stack.pop_back();
            traversed.erase(visited.back());
            visited.pop_back();
        } else if (visited.size() < cutoff) {
            auto child = **ai;
            ++(*ai);
            if (child == vd_target)
            {
                auto new_path = std::vector<vertd>(visited);
                new_path.push_back(child);
                paths.emplace_back(new_path);
            } else if (traversed.find(child) == traversed.end() and vulnerable_or_ignorable(G.to_np(child))) {
                visited.push_back(child);
                traversed.insert(child);
                stack.emplace_back(G.adjacent_vertices(child));
            }
        } else {
            auto child = **ai;
            if (child == vd_target or std::find(*ai, *ai_end, vd_target) != *ai_end)
            {
                auto new_path = std::vector<vertd>(visited);
                new_path.push_back(vd_target);
                paths.emplace_back(new_path);
            }
            stack.pop_back();
            traversed.erase(visited.back());
            visited.pop_back();
        }
    }

    for (auto& path : paths)
    {
        auto cpath = std::vector<T*>();
        for (auto& node : path)
        {
            cpath.push_back(G.to_np(node));
        }
        finals.push_back(cpath);
    }
    return finals;
}


}
#endif
