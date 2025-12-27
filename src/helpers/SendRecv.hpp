#pragma once

#include <string>
#include <string_view>

namespace Hyprauth {
    bool sendView(int fd, const std::string_view sv);
    bool recvView(int fd, std::string& buf);
}
