#pragma once
#include "proxy_core.h"

namespace proxy {
// Returns the complete, private stdin configuration for the pinned GOST engine.
// Call validate first. Never write this return value to a log or a disk file.
std::string buildGostConfig(const Config& config, unsigned short metricsPort,
                            const std::string& metricsPassword);
}
