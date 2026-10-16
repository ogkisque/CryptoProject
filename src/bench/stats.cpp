#include "vault/bench/stats.hpp"

#include <algorithm>
#include <cmath>
#include <numeric>
#include <vector>

namespace vault::bench {

Summary summarize(std::span<const double> samples) {
    Summary s;
    s.n = samples.size();
    if (s.n == 0) return s;
    std::vector<double> v(samples.begin(), samples.end());
    std::sort(v.begin(), v.end());
    s.min = v.front();
    s.max = v.back();
    s.mean = std::accumulate(v.begin(), v.end(), 0.0) / static_cast<double>(s.n);
    s.median = s.n % 2 ? v[s.n / 2] : (v[s.n / 2 - 1] + v[s.n / 2]) / 2;
    if (s.n > 1) {
        double acc = 0;
        for (double x : v) acc += (x - s.mean) * (x - s.mean);
        s.stddev = std::sqrt(acc / static_cast<double>(s.n - 1));  // выборочное (n-1)
    }
    return s;
}

}  // namespace vault::bench
