#include "parser/SSHParser.hpp"

#include <regex>

std::optional<SecurityEvent> SSHParser::parse(
    const std::string& line
) const {

    if (line.find("Failed password") != std::string::npos) {
        return parseAuthenticationFailure(line);
    }

    if (line.find("Accepted password") != std::string::npos ||
        line.find("Accepted publickey") != std::string::npos) {
        return parseAuthenticationSuccess(line);
    }

    return std::nullopt;
}

std::optional<SecurityEvent> SSHParser::parseAuthenticationFailure(
    const std::string& line
) const {

    static const std::regex pattern(
        R"((\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sshd\[\d+\]: Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+))"
    );

    std::smatch match;

    if (!std::regex_search(line, match, pattern)) {
        return std::nullopt;
    }

    SecurityEvent event;

    event.timestamp = match[1].str();
    event.hostname = match[2].str();
    event.source = "sshd";
    event.event_type = EventType::AUTHENTICATION_FAILURE;
    event.severity = Severity::MEDIUM;
    event.username = match[3].str();
    event.source_ip = match[4].str();
    event.source_port = std::stoi(match[5].str());

    return event;
}

std::optional<SecurityEvent> SSHParser::parseAuthenticationSuccess(
    const std::string& line
) const {

    static const std::regex pattern(
        R"((\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sshd\[\d+\]: Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+))"
    );

    std::smatch match;

    if (!std::regex_search(line, match, pattern)) {
        return std::nullopt;
    }

    SecurityEvent event;

    event.timestamp = match[1].str();
    event.hostname = match[2].str();
    event.source = "sshd";
    event.event_type = EventType::AUTHENTICATION_SUCCESS;
    event.severity = Severity::INFO;
    event.username = match[3].str();
    event.source_ip = match[4].str();
    event.source_port = std::stoi(match[5].str());

    return event;
}