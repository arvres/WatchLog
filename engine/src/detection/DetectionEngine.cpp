#include "detection/DetectionEngine.hpp"

void DetectionEngine::addRule(
    std::unique_ptr<DetectionRule> rule
) {
    rules.push_back(std::move(rule));
}

std::vector<Alert> DetectionEngine::process(
    const SecurityEvent& event
) {

    std::vector<Alert> alerts;

    for (const auto& rule : rules) {

        auto alert = rule->evaluate(event);

        if (alert.has_value()) {
            alerts.push_back(alert.value());
        }
    }

    return alerts;
}