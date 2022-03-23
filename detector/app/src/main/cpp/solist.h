#pragma once

#include <set>
#include <string_view>

namespace Solist {
    std::set<std::string_view> FindPathsFromSolist(std::string_view keyword);

    std::string FindZygiskFromPreloads();
}
