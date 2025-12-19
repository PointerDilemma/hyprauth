#pragma once

#include <string>

namespace Hyprauth::Env {
    bool envEnabled(const std::string& env);
    bool isTrace();
}
