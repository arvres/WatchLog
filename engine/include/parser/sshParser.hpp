#pragma once

#include "LogParser.hpp"

#include <optional>
#include <regex>
#include <string>

class SSHParser : public LogParser {
public:
    std::optional<SecurityEvent> parse(
        const std::string& line
    ) const override;

private:
    std::optional<SecurityEvent> parseAuthenticationFailure(
        const std::string& line
    ) const;

    std::optional<SecurityEvent> parseAuthenticationSuccess(
        const std::string& line
    ) const;
};