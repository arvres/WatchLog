#pragma once

#include <functional>
#include <string>

class LogReader {
public:
    explicit LogReader(const std::string& file_path);

    void read(
        const std::function<void(const std::string&)>& callback
    ) const;

private:
    std::string file_path;
};