#pragma once

#include "detection/DetectionRule.hpp"

#include <memory>
#include <vector>

class DetectionEngine {

public:

    void addRule(
        std::unique_ptr<DetectionRule> rule
    );

    std::vector<Alert> process(
        const SecurityEvent& event
    );

private:

    std::vector<std::unique_ptr<DetectionRule>> rules;
};