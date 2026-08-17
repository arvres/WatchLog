#pragma once

#include "../models/SecurityEvent.hpp"

#include <optional>
#include <string>

class LogParser {
public:
    virtual ~LogParser() = default;

    virtual std::optional<SecurityEvent> parse(
        const std::string& line
    ) const = 0;
};