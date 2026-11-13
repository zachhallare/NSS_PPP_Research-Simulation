"""Workload: Poisson arrivals, lognormal holding times, IP packet-size mix."""
import math

# Trimodal IP packet-size mix by packet count (ACK-sized / 576 B / full 1500 B), 7:4:1.
# Assumption, not measured traffic. 1500-B packets reach the BNG only without TCP MSS clamping
# (e.g. UDP/QUIC or tunnels), so the share of 1500-B packets is swept in a sensitivity run.
PACKET_MIX = [(40, 7), (576, 4), (1500, 1)]


def mix_with_full_share(share):
    """Same 40/576 ratio (7:4), with `share` of packets at 1500 B."""
    return [(40, (1 - share) * 7 / 11), (576, (1 - share) * 4 / 11), (1500, share)]


def lognormal_params(mean, cv):
    """(mu, sigma) of a lognormal with the given mean and coefficient of variation."""
    s2 = math.log(1 + cv * cv)
    return math.log(mean) - s2 / 2, math.sqrt(s2)


def holding_sampler(rng, mean, cv):
    if cv == 0:
        return lambda: mean
    mu, sigma = lognormal_params(mean, cv)
    return lambda: rng.lognormvariate(mu, sigma)


if __name__ == "__main__":
    import random
    import statistics
    r = random.Random(1)
    xs = [holding_sampler(r, 60.0, 1.5)() for _ in range(200_000)]
    m, cv = statistics.fmean(xs), statistics.pstdev(xs) / statistics.fmean(xs)
    assert abs(m - 60) < 1.5 and abs(cv - 1.5) < 0.15, (m, cv)
    print(f"lognormal ok: mean={m:.2f} cv={cv:.3f}")
