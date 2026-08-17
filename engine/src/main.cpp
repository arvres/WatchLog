#include "models/SecurityEventJson.hpp"
#include "parser/SSHParser.hpp"
#include "reader/LogReader.hpp"
#include "detection/BruteForceRule.hpp"
#include "detection/DetectionEngine.hpp"

#include <iostream>
#include <memory>

int main(int argc, char* argv[]) {

    if (argc != 2) {

        std::cerr
            << "Usage: WATCHLOG <log-file>\n";

        return 1;
    }

    const std::string logFile = argv[1];

    try {

        LogReader reader(logFile);
        SSHParser parser;

        DetectionEngine detectionEngine;

        detectionEngine.addRule(
            std::make_unique<BruteForceRule>(5)
        );

        reader.read([&parser, &detectionEngine](const std::string& line) {

            auto event = parser.parse(line);

            if (!event.has_value()) {
                return;
            }

            std::cout
                << toJson(event.value()).dump()
                << '\n';

            auto alerts = detectionEngine.process(
                event.value()
            );

            for (const auto& alert : alerts) {

                std::cout
                    << "[ALERT] "
                    << alert.message
                    << " | IP: "
                    << alert.source_ip
                    << " | Attempts: "
                    << alert.event_count
                    << '\n';
            }
        });

    } catch (const std::exception& exception) {

        std::cerr
            << "Error: "
            << exception.what()
            << '\n';

        return 1;
    }

    return 0;
}