#pragma once
// Статистика серии измерений (§49).

#include <cstddef>
#include <span>

namespace vault::bench {

struct Summary {
    std::size_t n = 0;
    double mean = 0, median = 0, min = 0, max = 0, stddev = 0;  // stddev выборочное (n-1)
};

Summary summarize(std::span<const double> samples);

}  // namespace vault::bench
