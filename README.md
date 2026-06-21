# mod_bw v2

A per-VirtualHost bandwidth and connection limiter for Apache 2.4.

This is a from-scratch v2 of mod_bw. It has been developed and run privately
over the last decade or so. Publishing it kept slipping: the earlier 0.x release
went on working with little maintenance, and time was short. I am opening it now
that I am confident every feature can be released in the open.

> **Work in progress.** The core limiter has been stable for years. The
> management API, and changing pools live without a restart, are newer:
> exercised with synthetic load and on a moderately busy (not extreme)
> production server over the last two years. Treat those parts as still
> maturing.

## What it does

Bandwidth and connection limits arranged as a tree of pools, evaluated per
request and shared live across all Apache processes:

- Hierarchical limits: VirtualHost > Pool > Rule, held in one shared-memory
  region linked by slot indices, so limits survive a graceful restart and work
  under the prefork, worker and event MPMs.
- Rule matching by User-Agent, client IP/CIDR, reverse-DNS host, or catch-all,
  with a fair-share-per-connection rate.
- Several enforcement mechanisms, selectable per directive; the rate is computed
  the same way for all of them:
  - egress: `sleep` (portable), `pacing` (SO_MAX_PACING_RATE), `tc` (a DSCP
    class for an external HTB qdisc), `mark` (SO_MARK fwmark).
  - ingress: `sleep`, `clamp` (TCP receive window), `mark`.
- Per-request overrides through environment variables (`BW_RATE`, `BW_IN_RATE`,
  `BW_MODE`, and friends), so `SetEnvIf` or mod_rewrite can adjust a single
  request without touching the pool tree.
- A REST management API for live reconfiguration, with scoped bearer tokens on
  top of a root configuration token.

See `example.conf` for a worked configuration.

## Build

Needs the Apache dev headers (`apxs`), APR / APR-Util, and CMake.

    cmake -B build -S .
    cmake --build build

This produces `build/mod_bw.so`. The Linux kernel paths (pacing / tc / clamp /
mark) are compiled in by default and can be disabled individually; a `sleep`-only
build is fully portable. See the options at the top of `CMakeLists.txt`.

## License

Apache License 2.0. See `LICENSE`.
