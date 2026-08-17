#include "detection/BruteForceRule.hpp"

BruteForceRule::BruteForceRule(int threshold)
    : threshold(threshold) {
}

std::optional<Alert> BruteForceRule::evaluate(
    const SecurityEvent& event
) {

    if (event.event_type != EventType::AUTHENTICATION_FAILURE) {
        return std::nullopt;
    }

    if (!event.source_ip.has_value()) {
        return std::nullopt;
    }

    const std::string& ip = event.source_ip.value();

    const int attempts = ++failedAttempts[ip];

    if (attempts < threshold) {
        return std::nullopt;
    }

    Alert alert;

    alert.type = AlertType::SSH_BRUTE_FORCE;

    alert.severity = AlertSeverity::HIGH;

    alert.message =
        "Multiple failed SSH authentication attempts detected";

    alert.source_ip = ip;

    alert.username = event.username;

    alert.event_count = attempts;

    return alert;
}