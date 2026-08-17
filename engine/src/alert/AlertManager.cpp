#include "alert/AlertManager.hpp"

#include <iostream>

void AlertManager::handle(
    const Alert& alert
) {

    std::cout
        << "[ALERT] "
        << alert.message
        << " | IP: "
        << alert.source_ip
        << " | Attempts: "
        << alert.event_count
        << '\n';
}