#pragma once

#include <chrono>

template <class DT = std::chrono::milliseconds,
    class ClockT = std::chrono::steady_clock>
class Timer
{
    using timep_t = typename ClockT::time_point;
    timep_t _start = ClockT::now(), _end = {};

public:
    void tick() {
        _end = timep_t{};
        _start = ClockT::now();
    }

    void tock() { _end = ClockT::now(); }

    template <class T = DT>
    auto elapsed() const {
        return std::chrono::duration_cast<T>(_end - _start).count();
    }
};