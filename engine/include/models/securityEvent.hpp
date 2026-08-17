#pragma once

#include <string>
#include <optional>

enum class EventType { // tipos de eventos de segurança
    UNKNOWN,
    AUTHENTICATION_FAILURE,
    AUTHENTICATION_SUCCESS
};

enum class Severity { // tipos de severidade de eventos de segurança
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

struct SecurityEvent {
    std::string timestamp;
    std::string hostname;
    std::string source;
    EventType event_type;
    Severity severity;

    std::optional<std::string> source_ip;
    std::optional<std::string> username;
    std::optional<int> source_port;
};