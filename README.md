# strx

A high-performance, heuristic drop-in replacement for the Unix `strings` tool, written in Rust.

## Features

- **Fast Execution**: Built with Rust for maximum performance and safety.
- **Advanced Heuristics**: Smarter extraction of strings compared to the traditional tool.
- **Pattern Matching**: Integrated regex and exact pattern searching.
- **Multiple Encodings**: Handles various text encodings gracefully (e.g., UTF-16).
- **Flexible Output**: Supports JSON output and colored terminal formatting.

## Installation

Ensure you have [Rust](https://www.rust-lang.org/tools/install) installed. Then run:

```bash
cargo build --release
```

The compiled binary will be available in `target/release/strx`.

## Usage

Basic usage is similar to the traditional `strings` tool:

```bash
strx <path/to/binary/file>
```

For more options, run:

```bash
strx --help
```

## License

This project is licensed under the MIT License.
