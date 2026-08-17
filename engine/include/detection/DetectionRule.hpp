#pragma once

#include "models/Alert.hpp"
#include "models/SecurityEvent.hpp"

#include <optional>

class DetectionRule {

public:

    virtual ~DetectionRule() = default;

    virtual std::optional<Alert> evaluate(
        const SecurityEvent& event
    ) = 0;
};