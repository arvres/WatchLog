#pragma once

#include "detection/DetectionRule.hpp"

#include <string>
#include <unordered_map>

class BruteForceRule : public DetectionRule {

public:

    explicit BruteForceRule(
        int threshold = 5
    );

    std::optional<Alert> evaluate(
        const SecurityEvent& event
    ) override;

private:

    int threshold;

    std::unordered_map<std::string, int> failedAttempts;
};