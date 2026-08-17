#include "models/SecurityEventJson.hpp"
#include "parser/SSHParser.hpp"
#include "reader/LogReader.hpp"

#include <iostream>
#include <string>

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

        reader.read([&parser](const std::string& line) {

            auto event = parser.parse(line);

            if (!event.has_value()) {
                return;
            }

            std::cout
                << toJson(event.value()).dump()
                << '\n';
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