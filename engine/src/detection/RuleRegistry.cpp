#include "detection/RuleRegistry.hpp"

#include "detection/BruteForceRule.hpp"
#include "detection/PasswordSprayRule.hpp"

#include <memory>

DetectionEngine createDefaultDetectionEngine() {

    DetectionEngine engine;

    engine.addRule(
        std::make_unique<BruteForceRule>(5)
    );

    engine.addRule(
        std::make_unique<PasswordSprayRule>(5)
    );

    return engine;
}