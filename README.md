# Sparkle Pony

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-blue.svg)](https://www.rust-lang.org)

High-performance email contact extractor for Microsoft Outlook PST files.

## Features

- **Fast PST Parsing**: Native Rust PST parsing via the `outlook-pst` crate
- **Parallel Processing**: Multi-threaded extraction using Rayon
- **Smart Filtering**:
  - Configurable blacklist for spam/invalid addresses (RON config)
  - TLD validation against IANA registry
  - Email format validation with regex
- **Resource Management**: Configurable CPU/memory limits with real-time monitoring
- **Deduplication**: Automatic removal of duplicate contacts
- **CSV Output**: Clean, deduplicated contact lists

## Installation

### From Source

```bash
git clone https://github.com/greysquirr3l/sparklepony.git
cd sparklepony
cargo build --release
```

The binary will be available at `target/release/pst_weee`.

### Prerequisites

- Rust 1.70 or later
- Cargo

## Usage

### Basic Usage

```bash
# Extract contacts from a single PST file
pst_weee -i inbox.pst -o contacts.csv

# Process all PST files in a directory
pst_weee -i /path/to/pst/folder -o contacts.csv
```

### Advanced Options

```bash
# Limit resource usage
pst_weee -i inbox.pst --cpu 50 --memory 60 --min-free-memory 4

# Use safe mode (conservative resource limits)
pst_weee -i inbox.pst --safe

# Set worker thread count
pst_weee -i inbox.pst -w 4

# Disable TLD filtering
pst_weee -i inbox.pst --disable-tld-filter

# Enable debug logging
pst_weee -i inbox.pst --debug
```

### All Options

| Option | Short | Default | Description |
| -------- | ------- | --------- | ------------- |
| `--input` | `-i` | Required | Path to PST file or folder |
| `--output` | `-o` | `contacts.csv` | Output CSV file path |
| `--cpu` | | `70.0` | Max CPU usage percentage |
| `--memory` | | `70.0` | Max memory usage percentage |
| `--min-free-memory` | | `2` | Minimum free memory (GB) |
| `--workers` | `-w` | `0` (auto) | Worker thread count |
| `--safe` | | false | Enable safe mode |
| `--debug` | | false | Enable debug logging |
| `--disable-tld-filter` | | false | Skip TLD validation |
| `--ignore-space-check` | | false | Skip disk space check |

## Configuration

### Blacklist Configuration

Email filtering rules are configurable via `config/blacklist.ron`:

```ron
BlacklistConfig(
    blacklisted_terms: [
        "noreply",
        "no-reply",
        "donotreply",
        // ... more terms
    ],
    bad_patterns: [
        "@example.com",
        "@test.com",
        // ... more patterns
    ],
)
```

## Output Format

The CSV output contains:

| Column | Description |
| -------- | ------------- |
| `email` | Email address |
| `name` | Contact name (if available) |
| `source` | Source PST file |

## Architecture

```text
src/
├── cli/          # Command-line interface (clap)
├── config/       # Configuration handling
├── filter/       # Email validation & filtering
│   ├── email.rs  # Blacklist filtering
│   └── tld.rs    # TLD validation
├── output/       # CSV writer
├── processor/    # Orchestration
├── progress/     # Progress tracking
├── pst/          # PST extraction
└── resource/     # System resource monitoring
```

## Performance

- Parallel folder traversal with Rayon
- DashMap for concurrent deduplication
- Configurable resource limits prevent system overload
- Streaming writes to minimize memory footprint

## Development

```bash
# Run tests
cargo test

# Run with all warnings
cargo clippy --all-targets --all-features -- -W clippy::pedantic

# Build release
cargo build --release

# Run benchmarks
cargo bench
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Security

For security concerns, please see [SECURITY.md](SECURITY.md).
