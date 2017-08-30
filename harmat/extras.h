#include <algorithm>
#include <bglgraph.h>

namespace harmat {
template <typename T>
bool is_ignorable(const T& np)
{
    if (np->ignorable)
        return true
    return false
}


template <typename T>
void filter_ignorables(std::vector<T*> nodes)
{
    nodes.erase(std::remove_if(nodes.begin(), nodes.end(), is_ignorable), nodes.end());
}
}