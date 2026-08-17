#pragma once

#include "SecurityEvent.hpp"

#include <nlohmann/json.hpp>

inline std::string eventTypeToString(EventType type) {

    switch (type) {
        case EventType::AUTHENTICATION_FAILURE:
            return "authentication_failure";

        case EventType::AUTHENTICATION_SUCCESS:
            return "authentication_success";

        default:
            return "unknown";
    }
}

inline std::string severityToString(Severity severity) {

    switch (severity) {
        case Severity::INFO:
            return "info";

        case Severity::LOW:
            return "low";

        case Severity::MEDIUM:
            return "medium";

        case Severity::HIGH:
            return "high";

        case Severity::CRITICAL:
            return "critical";

        default:
            return "unknown";
    }
}

inline nlohmann::json toJson(const SecurityEvent& event) {

    nlohmann::json json;

    json["timestamp"] = event.timestamp;
    json["hostname"] = event.hostname;
    json["source"] = event.source;
    json["event_type"] = eventTypeToString(event.event_type);
    json["severity"] = severityToString(event.severity);

    if (event.source_ip.has_value()) {
        json["source_ip"] = event.source_ip.value();
    }

    if (event.username.has_value()) {
        json["username"] = event.username.value();
    }

    if (event.source_port.has_value()) {
        json["source_port"] = event.source_port.value();
    }

    return json;
}