"""Statistics helpers: 95% t-intervals, Welch test, Erlang B, 1%-blocking crossing. Stdlib only."""
import math
import statistics

# Two-sided 97.5% Student-t quantiles (exact table values for the df used here).
_T975 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262,
         10: 2.228, 14: 2.145, 19: 2.093, 20: 2.086, 25: 2.060, 29: 2.045, 30: 2.042, 40: 2.021,
         58: 2.002, 60: 2.000, 120: 1.980}


def t975(df):
    if df in _T975:
        return _T975[df]
    z = 1.959964  # Cornish-Fisher expansion, accurate to ~1e-3 for df >= 3
    return z + (z**3 + z) / (4 * df) + (5 * z**5 + 16 * z**3 + 3 * z) / (96 * df**2)


def mean_ci(xs):
    xs = [x for x in xs if x == x]  # drop NaN
    n = len(xs)
    if n == 0:
        return float("nan"), float("nan")
    m = statistics.fmean(xs)
    return m, (t975(n - 1) * statistics.stdev(xs) / math.sqrt(n) if n > 1 else 0.0)


def welch_significant(a, b):
    """Two-sided Welch t-test at 5%. Returns (t, df, significant)."""
    na, nb = len(a), len(b)
    va, vb = statistics.variance(a) / na, statistics.variance(b) / nb
    if va + vb == 0:
        return float("inf"), na + nb - 2, statistics.fmean(a) != statistics.fmean(b)
    t = (statistics.fmean(a) - statistics.fmean(b)) / math.sqrt(va + vb)
    df = (va + vb) ** 2 / (va**2 / (na - 1) + vb**2 / (nb - 1))
    return t, df, abs(t) > t975(max(1, round(df)))


def paired_significant(a, b):
    """Paired t-test at 5% (common random numbers, e.g. MTU 1492 vs 1500 in the same run)."""
    d = [x - y for x, y in zip(a, b)]
    m, h = mean_ci(d)
    return m, h, abs(m) > h


def erlang_b(A, C):
    B = 1.0
    for k in range(1, C + 1):
        B = A * B / (k + A * B)
    return B


def crossing(xs, ys, target=0.01):
    """First x where piecewise-linear y(x) reaches target; None if it never does (right-censored)."""
    if ys[0] >= target:
        return xs[0]
    for (x0, y0), (x1, y1) in zip(zip(xs, ys), zip(xs[1:], ys[1:])):
        if y1 >= target:
            return x0 + (target - y0) * (x1 - x0) / (y1 - y0)
    return None


if __name__ == "__main__":
    assert abs(erlang_b(10, 10) - 0.2146) < 1e-3
    assert abs(t975(29) - 2.045) < 1e-9 and abs(t975(50) - 2.009) < 2e-3
    assert crossing([0.5, 1.0], [0.0, 0.02]) == 0.75 and crossing([1, 2], [0, 0.001]) is None
    print("metrics ok")
