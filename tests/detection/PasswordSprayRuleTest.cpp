#include "detection/PasswordSprayRule.hpp"

#include <gtest/gtest.h>


TEST(PasswordSprayRuleTest, DoesNotAlertBeforeThreshold) {

    PasswordSprayRule rule(5);

    const char* users[] = {
        "admin",
        "root",
        "guest",
        "test"
    };

    for (const auto* username : users) {

        SecurityEvent event;

        event.event_type =
            EventType::AUTHENTICATION_FAILURE;

        event.source_ip =
            "192.168.1.50";

        event.username =
            username;

        auto alert =
            rule.evaluate(event);

        EXPECT_FALSE(alert.has_value());
    }
}


TEST(PasswordSprayRuleTest, AlertsWhenMultipleUsersAreTargeted) {

    PasswordSprayRule rule(5);

    const char* users[] = {
        "admin",
        "root",
        "guest",
        "test",
        "user"
    };

    std::optional<Alert> alert;

    for (const auto* username : users) {

        SecurityEvent event;

        event.event_type =
            EventType::AUTHENTICATION_FAILURE;

        event.source_ip =
            "192.168.1.50";

        event.username =
            username;

        alert = rule.evaluate(event);
    }

    ASSERT_TRUE(alert.has_value());

    EXPECT_EQ(
        alert->type,
        AlertType::SSH_PASSWORD_SPRAY
    );

    EXPECT_EQ(
        alert->severity,
        AlertSeverity::HIGH
    );

    EXPECT_EQ(
        alert->source_ip,
        "192.168.1.50"
    );

    EXPECT_EQ(
        alert->event_count,
        5
    );
}


TEST(PasswordSprayRuleTest, RepeatedUsernameDoesNotIncreaseCount) {

    PasswordSprayRule rule(5);

    const char* users[] = {
        "admin",
        "admin",
        "admin",
        "root"
    };

    for (const auto* username : users) {

        SecurityEvent event;

        event.event_type =
            EventType::AUTHENTICATION_FAILURE;

        event.source_ip =
            "192.168.1.50";

        event.username =
            username;

        auto alert =
            rule.evaluate(event);

        EXPECT_FALSE(alert.has_value());
    }
}


TEST(PasswordSprayRuleTest, IgnoresEventsWithoutUsername) {

    PasswordSprayRule rule(5);

    SecurityEvent event;

    event.event_type =
        EventType::AUTHENTICATION_FAILURE;

    event.source_ip =
        "192.168.1.50";

    auto alert =
        rule.evaluate(event);

    EXPECT_FALSE(alert.has_value());
}