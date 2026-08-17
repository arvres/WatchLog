#pragma once

#include <optional>
#include <string>

enum class AlertSeverity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

enum class AlertType {
    SSH_BRUTE_FORCE,
    SSH_PASSWORD_SPRAY,
    SUSPICIOUS_LOGIN,
    INVALID_USER_ATTACK,
    PRIVILEGE_ESCALATION
};

struct Alert {

    AlertType type;

    AlertSeverity severity;

    std::string message;

    std::string source_ip;

    std::optional<std::string> username;

    int event_count = 0;
};