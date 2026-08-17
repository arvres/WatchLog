#pragma once

#include "detection/DetectionRule.hpp"

#include <string>
#include <unordered_map>
#include <unordered_set>

class PasswordSprayRule : public DetectionRule {

public:

    explicit PasswordSprayRule(
        int threshold = 5
    );

    std::optional<Alert> evaluate(
        const SecurityEvent& event
    ) override;

private:

    int threshold;

    std::unordered_map<
        std::string,
        std::unordered_set<std::string>
    > targetedUsers;

    std::unordered_map<std::string, bool> alerted;
};