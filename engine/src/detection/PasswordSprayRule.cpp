#include "detection/PasswordSprayRule.hpp"

PasswordSprayRule::PasswordSprayRule(int threshold)
    : threshold(threshold) {
}

std::optional<Alert> PasswordSprayRule::evaluate(
    const SecurityEvent& event
) {

    if (event.event_type != EventType::AUTHENTICATION_FAILURE) {
        return std::nullopt;
    }

    if (!event.source_ip.has_value()) {
        return std::nullopt;
    }

    if (!event.username.has_value()) {
        return std::nullopt;
    }

    const std::string& ip =
        event.source_ip.value();

    const std::string& username =
        event.username.value();

    targetedUsers[ip].insert(username);

    const std::size_t uniqueUsers =
        targetedUsers[ip].size();

    if (uniqueUsers < static_cast<std::size_t>(threshold)) {
        return std::nullopt;
    }

    if (alerted[ip]) {
        return std::nullopt;
    }

    alerted[ip] = true;

    Alert alert;

    alert.type =
        AlertType::SSH_PASSWORD_SPRAY;

    alert.severity =
        AlertSeverity::HIGH;

    alert.message =
        "Multiple user accounts targeted from the same source";

    alert.source_ip = ip;

    alert.username = username;

    alert.event_count =
        static_cast<int>(uniqueUsers);

    return alert;
}