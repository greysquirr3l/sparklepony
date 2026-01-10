# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-01-10

### Added

- External blacklist configuration via RON file (`config/blacklist.ron`)
- TLD validation against IANA registry
- Resource monitoring with configurable CPU/memory limits
- Progress tracking with indicatif
- Safe mode for conservative resource usage
- Comprehensive test suite (28 tests)
- Benchmark suite for extraction performance
- Architecture documentation

### Changed

- Replaced `lazy_static` with `std::sync::LazyLock`
- Improved email validation with configurable patterns
- Enhanced error handling with `thiserror`

### Fixed

- All clippy pedantic warnings resolved
- Self-recursion pattern in folder traversal

## [0.1.0] - 2026-01-09

### Added

- Initial PST parsing with `outlook-pst` crate
- Basic email extraction
- CSV output with deduplication
- CLI with clap argument parsing
- Parallel processing with rayon
- Basic email filtering

[Unreleased]: https://github.com/greysquirr3l/sparklepony/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/greysquirr3l/sparklepony/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/greysquirr3l/sparklepony/releases/tag/v0.1.0
