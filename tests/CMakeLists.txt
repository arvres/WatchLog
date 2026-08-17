add_executable(WATCHLOG-tests

    detection/BruteForceRuleTest.cpp

    detection/DetectionEngineTest.cpp
)

target_link_libraries(WATCHLOG-tests

    PRIVATE
        WATCHLOG-engine-core
        GTest::gtest_main
)

include(GoogleTest)

gtest_discover_tests(WATCHLOG-tests)