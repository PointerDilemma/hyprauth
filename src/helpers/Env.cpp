#include "Env.hpp"

#include <cstdlib>
#include <string_view>

using namespace Hyprauth;
using namespace Hyprauth::Env;

bool Hyprauth::Env::envEnabled(const std::string& env) {
    auto ret = getenv(env.c_str());
    if (!ret)
        return false;

    const std::string_view sv = ret;

    return !sv.empty() && sv != "0";
}

bool Hyprauth::Env::isTrace() {
    static bool TRACE = envEnabled("HA_TRACE");
    return TRACE;
}

bool Hyprauth::Env::isDebug() {
    static bool DEBUG = envEnabled("HA_DEBUG");
    return DEBUG;
}
