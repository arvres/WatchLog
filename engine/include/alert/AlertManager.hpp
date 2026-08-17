#pragma once

#include "models/Alert.hpp"

class AlertManager {

public:

    void handle(
        const Alert& alert
    );
};