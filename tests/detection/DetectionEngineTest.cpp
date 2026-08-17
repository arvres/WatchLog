#include "detection/BruteForceRule.hpp"
#include "detection/DetectionEngine.hpp"

#include <gtest/gtest.h>

#include <memory>


TEST(DetectionEngineTest, GeneratesBruteForceAlert) {

    DetectionEngine engine;

    engine.addRule(
        std::make_unique<BruteForceRule>(5)
    );

    SecurityEvent event;

    event.event_type = EventType::AUTHENTICATION_FAILURE;
    event.source_ip = "192.168.1.50";
    event.username = "admin";

    for (int i = 0; i < 4; ++i) {

        auto alerts = engine.process(event);

        EXPECT_TRUE(alerts.empty());
    }

    auto alerts = engine.process(event);

    ASSERT_EQ(alerts.size(), 1);

    EXPECT_EQ(
        alerts[0].type,
        AlertType::SSH_BRUTE_FORCE
    );

    EXPECT_EQ(
        alerts[0].severity,
        AlertSeverity::HIGH
    );

    EXPECT_EQ(
        alerts[0].event_count,
        5
    );
}