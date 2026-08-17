#include "reader/LogReader.hpp"

#include <fstream>
#include <stdexcept>

LogReader::LogReader(const std::string& file_path)
    : file_path(file_path) {
}

void LogReader::read(
    const std::function<void(const std::string&)>& callback
) const {

    std::ifstream file(file_path);

    if (!file.is_open()) {
        throw std::runtime_error(
            "Unable to open log file: " + file_path
        );
    }

    std::string line;

    while (std::getline(file, line)) {
        callback(line);
    }
}