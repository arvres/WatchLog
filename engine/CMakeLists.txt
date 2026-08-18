add_library(WATCHLOG-engine-core

    src/parser/SSHParser.cpp

    src/reader/LogReader.cpp

    src/detection/BruteForceRule.cpp

    src/detection/DetectionEngine.cpp

    src/detection/PasswordSprayRule.cpp

    src/alert/AlertManager.cpp

    src/detection/RuleRegistry.cpp
)

target_include_directories(WATCHLOG-engine-core

    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(WATCHLOG-engine-core

    PUBLIC
        nlohmann_json::nlohmann_json
)

target_compile_features(WATCHLOG-engine-core

    PUBLIC
        cxx_std_20
)

target_compile_options(WATCHLOG-engine-core

    PRIVATE
        -Wall
        -Wextra
        -Wpedantic
)


add_executable(WATCHLOG

    src/main.cpp
)

target_link_libraries(WATCHLOG

    PRIVATE
        WATCHLOG-engine-core
)