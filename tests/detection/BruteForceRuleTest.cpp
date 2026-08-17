#include "detection/BruteForceRule.hpp"

#include <gtest/gtest.h>

TEST(BruteForceRuleTest, DoesNotAlertBeforeThreshold) {

    BruteForceRule rule(5);

    SecurityEvent event;

    event.event_type = EventType::AUTHENTICATION_FAILURE;
    event.source_ip = "192.168.1.50";
    event.username = "admin";

    for (int i = 0; i < 4; ++i) {

        auto alert = rule.evaluate(event);

        EXPECT_FALSE(alert.has_value());
    }
}


TEST(BruteForceRuleTest, AlertsWhenThresholdIsReached) {

    BruteForceRule rule(5);

    SecurityEvent event;

    event.event_type = EventType::AUTHENTICATION_FAILURE;
    event.source_ip = "192.168.1.50";
    event.username = "admin";

    for (int i = 0; i < 4; ++i) {

        auto alert = rule.evaluate(event);

        EXPECT_FALSE(alert.has_value());
    }

    auto alert = rule.evaluate(event);

    ASSERT_TRUE(alert.has_value());

    EXPECT_EQ(
        alert->type,
        AlertType::SSH_BRUTE_FORCE
    );

    EXPECT_EQ(
        alert->severity,
        AlertSeverity::HIGH
    );

    EXPECT_EQ(
        alert->source_ip,
        "192.168.1.50"
    );

    ASSERT_TRUE(alert->username.has_value());

    EXPECT_EQ(
        alert->username.value(),
        "admin"
    );

    EXPECT_EQ(
        alert->event_count,
        5
    );
}


TEST(BruteForceRuleTest, IgnoresSuccessfulAuthentication) {

    BruteForceRule rule(5);

    SecurityEvent event;

    event.event_type = EventType::AUTHENTICATION_SUCCESS;
    event.source_ip = "192.168.1.50";
    event.username = "admin";

    auto alert = rule.evaluate(event);

    EXPECT_FALSE(alert.has_value());
}


TEST(BruteForceRuleTest, IgnoresEventsWithoutSourceIp) {

    BruteForceRule rule(5);

    SecurityEvent event;

    event.event_type = EventType::AUTHENTICATION_FAILURE;
    event.username = "admin";

    auto alert = rule.evaluate(event);

    EXPECT_FALSE(alert.has_value());
}